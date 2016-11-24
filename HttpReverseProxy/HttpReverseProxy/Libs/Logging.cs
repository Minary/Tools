using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;


namespace HTTPReverseProxyServer
{
    public class Logging
    {

        #region MEMBERS

        private static Object cSyncObj = new object();
        private static List<String> cLogs = new List<String>();

        #endregion


        #region TYPE DEFINITIONS


        public enum Level:int
        {
            DEBUG = 1,
            INFO = 2,
            WARNING = 3,
            ERROR = 4
        }

        #endregion


        #region PUBLIC MESSAGE


        /*
         * 
         * 
         */
        public static void LogMessage(String pMsg, Level pLevel, int pMargin = 0)
        {
            if ((pLevel >= Config.LogLevel) && !String.IsNullOrEmpty(pMsg) && !String.IsNullOrWhiteSpace(pMsg))
            {
              String lTimestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
              String lMargin = String.Concat(Enumerable.Repeat(" ", pMargin*2));

              lock (cSyncObj)
              {
                  pMsg = pMsg.Trim();
                  String lLogLine = String.Format("{0} : {1}{2}{3}", lTimestamp, lMargin, pMsg, Environment.NewLine);
                  Console.Write(lLogLine);
                  cLogs.Add(lLogLine);
//                  File.AppendAllText(Config.Logfile, lLogLine);         
              } // lock (cSy...
            } // if (!Stri...
        }


        /*
         * 
         * 
         */
        public static List<String> FindLogRecordByRegex(String pSearchPattern)
        {
            List<String> lRecords = new List<String>();

            foreach (String lTmp in cLogs)
                if (Regex.Match(lTmp, pSearchPattern).Success)
                    lRecords.Add(lTmp);

            return lRecords;
        }


        /*
         * 
         * 
         */
        public static void ResetLogging()
        {
            cLogs.Clear();
        }

        #endregion

    }
}
