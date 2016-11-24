using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPReverseProxyServer
{

    public class HSTSRecord
    {

        #region MEMBER

        public int Counter = 0;
        public String Host;
        public Boolean EncryptSubdomains;

        #endregion

        #region PUBLIC METHODS

        public HSTSRecord(String pHost)
        {
            Host = pHost;
        }

        #endregion

    }



    public class HSTSCache
    {

        #region MEMBER

        private static HSTSCache cInstance;
        private Dictionary<String, HSTSRecord> cCache = new Dictionary<String, HSTSRecord>();

        #endregion


        #region PROPERTIES

        public static HSTSCache Instance { get { return cInstance ?? (cInstance = new HSTSCache()); } set { } }

        #endregion


        #region PUBLIC METHODS

        private  HSTSCache()
        {
        }



        /*
         * 
         * 
         */
        public void addElement(String pHost)
        {

            // Host checks
            if (String.IsNullOrEmpty(pHost) || String.IsNullOrWhiteSpace(pHost))
                throw new Exception("Something is wrong with the host name");

            // Return if element already exists
            if (cCache.ContainsKey(pHost))
                return;

            Logging.LogMessage(String.Format("HSTSCache.addElement() : Host => \"{0}\"", pHost), Logging.Level.DEBUG);

            HSTSRecord lTmpHost = new HSTSRecord(pHost);
            cCache.Add(pHost, lTmpHost);
        }


        /*
         * 
         * 
         */
        public void enumerateCache()
        {
            foreach (String lKey in cCache.Keys)
                Logging.LogMessage(String.Format("enumerateCache() : Host:\"{0}\"", lKey), Logging.Level.DEBUG);
        }


        /*
         * 
         * 
         */
        public void resetCache()
        {
            if (cCache != null)
                cCache.Clear();
        }


        /*
         * 
         * 
         */
        public bool deleteElement(String pHost)
        {
            if (String.IsNullOrEmpty(pHost) || String.IsNullOrWhiteSpace(pHost))
                throw new Exception("Something is wrong with the host name");

            if (cCache.ContainsKey(pHost))
                return cCache.Remove(pHost);

            return false;
        }



        /*
         * 
         * 
         */
        public HSTSRecord GetElement(String pHost)
        {
            if (String.IsNullOrEmpty(pHost) || String.IsNullOrWhiteSpace(pHost))
                throw new Exception("Something is wrong with the host name");

            if (!cCache.ContainsKey(pHost))
                return null;

            return cCache[pHost];
        }






        /*
         * 
         * 
         */
        public bool NeedsRequestBeMapped(String pHost)
        {
            if (!String.IsNullOrEmpty(pHost) && !String.IsNullOrWhiteSpace(pHost) && cCache.ContainsKey(pHost))
                return true;

            return false;
        }

        #endregion

    }

}
