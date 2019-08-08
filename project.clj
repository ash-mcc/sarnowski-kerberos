(defproject ash-mcc/sarnowski-kerberos "0.4.0"
  :description "A Clojure library for kerberos authentication."
  :url "https://github.com/sarnowski/kerberos"

  :license {:name "ISC"
            :url "http://www.isc.org/downloads/software-support-policy/isc-license/"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/data.codec "0.1.0"]
                 [org.clojure/tools.logging "0.3.1" :exclusions [org.clojure/tools.trace]]])
