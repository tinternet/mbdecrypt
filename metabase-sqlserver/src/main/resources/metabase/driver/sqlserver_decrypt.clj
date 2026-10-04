(ns metabase.driver.sqlserver-decrypt
  "SQL Server, supporting decryption of application-level encrypted columns."
  (:require
   [clojure.string :as str]
   [metabase.driver :as driver]
   [metabase.driver.sql-jdbc.connection :as sql-jdbc.conn]))

(driver/register! :sqlserver-decrypt, :parent :sqlserver)

(defn- decrypt-settings
  "The `decrypt-*` fields from the connection form. These become JDBC connection properties, we read and remove them before calling the parent."
  [details]
  (into {}
        (filter (fn [[k v]] (and (some? v) (str/starts-with? (name k) "decrypt-"))))
        details))

(defmethod sql-jdbc.conn/connection-details->spec :sqlserver-decrypt
  [driver details]
  (let [spec ((get-method sql-jdbc.conn/connection-details->spec :sqlserver) driver details)]
    ;; jdbc:sqlserver://... becomes jdbc:decrypt:sqlserver://...
    (merge spec
           (decrypt-settings details)
           {:subprotocol (str "decrypt:" (:subprotocol spec))
            :classname   "mbdecrypt.jdbc.DecryptingDriver"})))
