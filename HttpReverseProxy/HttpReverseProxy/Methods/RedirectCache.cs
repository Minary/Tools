using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace HTTPReverseProxyServer
{
    public class RedirectHost
    {

        #region MEMBERS

        public String Scheme;
        public String Method;
        public String Host;
        public String Path;
        private Int32 cCounter;

        #endregion


        #region PROPERTIES

        public String URL { get { return String.Format("{0}://{1}{2}", Scheme, Host, Path); }  }
        public Int32 Counter { get { return cCounter; } set { } }

        #endregion


        #region PUBLIC METHODS

        public RedirectHost(String pMethod, String pScheme, String pPhost, String pPath)
        {
            Method = pMethod;
            Scheme = pScheme;
            Host = pPhost;
            Path = pPath;
            cCounter = 0;
        }

        public void IncCounter()
        {
            cCounter++;
        }

        #endregion

    }

    public class RedirectCache
    {

        #region MEMBERS

        private static RedirectCache cInstance;
        private Dictionary<String, RedirectHost> cCache = new Dictionary<String, RedirectHost>();

        #endregion


        #region PROPERTIES

        public static RedirectCache Instance { get { return cInstance ?? (cInstance = new RedirectCache()); } set { } }

        #endregion



        #region PUBLIC METHODS


        

        /*
         * 
         * 
         */
        public void addElement(String pKeyLocation, String pValueLocation, Boolean pHSTSEnabled = false)
        {

            // Key value checks
            if (!Uri.IsWellFormedUriString(pKeyLocation, UriKind.Absolute))
                throw new Exception("Key Uri is not well formed");

            Uri lTmpUriKey = new Uri(pKeyLocation);
            if (lTmpUriKey == null || !Regex.Match(lTmpUriKey.Scheme, @"^https?$").Success)
                throw new Exception("Key Uri is not well formed");

            // Value URI checks
            if (!Uri.IsWellFormedUriString(pValueLocation, UriKind.Absolute))
                throw new Exception("Value Uri is not well formed");

            Uri lTmpUriValue = new Uri(pValueLocation);
            if (lTmpUriValue == null || !Regex.Match(lTmpUriValue.Scheme, @"^https?$").Success)
                throw new Exception("Value Uri is not well formed");

            if (this.NeedsRequestBeMapped(pKeyLocation))
                throw new Exception("Key was already added to the cache");

            Logging.LogMessage(String.Format("RedirectCache.addElement() : \"{0}\" => \"{1}\"", pKeyLocation, pValueLocation), Logging.Level.DEBUG);

            RedirectHost lTmpHost = new RedirectHost("GET", lTmpUriValue.Scheme, lTmpUriValue.Host, lTmpUriValue.PathAndQuery);
            cCache.Add(pKeyLocation, lTmpHost);
        }


        /*
         * 
         * 
         */
        public void enumerateCache()
        {
            foreach (String lKey in cCache.Keys)
            {
                Logging.LogMessage(String.Format("enumerateCache() : Key:{0} Value:\"{1}\", Counter:{2}", lKey, cCache[lKey].URL, cCache[lKey].Counter), Logging.Level.DEBUG);
            }
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
        public bool deleteElement(String pKeyURL)
        {
            if (!Uri.IsWellFormedUriString(pKeyURL, UriKind.Absolute))
                throw new Exception("Key Uri is not well formed");

            if (cCache.ContainsKey(pKeyURL))
                return cCache.Remove(pKeyURL);

            return false;
        }


        /*
         * 
         * 
         */
        public RedirectHost GetElement(String pURL)
        {
            if (!Uri.IsWellFormedUriString(pURL, UriKind.Absolute))
                throw new Exception("The URL is malformed");

            if (!cCache.ContainsKey(pURL))
                return null;

            return cCache[pURL];
        }


        /*
         * 
         * 
         */
        public bool NeedsRequestBeMapped(String pURL)
        {
            if (Uri.IsWellFormedUriString(pURL, UriKind.Absolute))
            {
                // http://www.buglist.io/test/boom/ignaz.html
                if (cCache.ContainsKey(pURL))
                    return true;

                // http://www.buglist.io/ and HSTS enabled
                Uri lTmpURI = new Uri(pURL);
                String lTmpRequestURL = String.Format("{0}://{1}/", lTmpURI.Scheme, lTmpURI.Host);

                if (cCache.ContainsKey(pURL))
                  return true;

            }

            return false;
        }

        #endregion


        #region PRIVATE METHODS

        private RedirectCache()
        {
        }

        #endregion


    }
}
