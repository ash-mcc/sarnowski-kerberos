(ns sarnowski.kerberos.spnego
  (:require [clojure.string :as s]
            [clojure.data.codec.base64 :as b64]
            [clojure.tools.logging :as log]
            [sarnowski.kerberos :as kerberos])
  (:import (javax.security.auth Subject)
           (org.ietf.jgss GSSException)
           (java.security GeneralSecurityException PrivilegedActionException)))

(def ^:private deny {:status 401
                     :headers {"WWW-Authenticate" "Negotiate"}
                     :body "Unauthorized access denied. You have to enable SPNEGO authentication for this domain in your browser."})

(defn- get-negotiate-token [request]
  (when-let [authorization (get (:headers request) "authorization")]
    (let [[method token] (s/split authorization #" ")]
      (when (= "Negotiate" method)
        (b64/decode (.getBytes token "UTF-8"))))))

(defn- authenticate-request [request service-subject token]
  (let [ticket (kerberos/validate-ticket service-subject token)]
    (merge request {:remote-user (str (:principal ticket))
                    :kerberos-ticket ticket})))

(defn authenticate
  "Applies SPNEGO authentication to the Ring handler.
  If successful, :remote-user and :kerberos-ticket entries are placed into the request map."
  [app #^Subject service-subject & {:keys [exempt? require? log-exceptions?]
                                    :or {exempt? (fn [_] false) 
                                         require? true
                                         log-exceptions? true}}]
  (letfn [(handle-exception [ex]
            (when log-exceptions?
              (log/error ex "surpressing internal error, denying access"))
            (merge deny {:exception ex}))]
    (fn [request]
      (if (exempt? request)
        (app request)
        (try
          (if-let [token (get-negotiate-token request)]
            (if-let [request* (authenticate-request request service-subject token)]
              (app request*)
              deny)
            (if require? 
              deny 
              (app request)))
          (catch PrivilegedActionException e (handle-exception e))
          (catch GSSException e (handle-exception e))
          (catch GeneralSecurityException e (handle-exception e)))))))

(defn authenticate-pedestal
  "Applies SPNEGO authentication to the Pedestal context.
  If successful, :remote-user and :kerberos-ticket entries are placed into the context's :request map."
  [context #^Subject service-subject & {:keys [exempt? require? log-exceptions?]
                                        :or {exempt? (fn [_] false) 
                                             require? true
                                             log-exceptions? true}}]
  (letfn [(handle-exception [ex]
            (when log-exceptions?
              (log/error ex "surpressing internal error, denying access"))
            (assoc context :response (merge deny {:exception ex})))]
    (let [request (:request context)]
      (if (exempt? request)
        context
        (try
          (if-let [token (get-negotiate-token request)]
            (if-let [request* (authenticate-request request service-subject token)]
              (assoc context :request request*)
              (assoc context :response deny))
            (if require? 
              (assoc context :response deny) 
              context))
          (catch PrivilegedActionException e (handle-exception e))
          (catch GSSException e (handle-exception e))
          (catch GeneralSecurityException e (handle-exception e)))))))