using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Collections;


namespace HTTPReverseProxyServer
{
  class HTTPRedirect
  {

    #region MEMBERS

    private static HTTPRedirect cInstance;

    #endregion


    #region PRIVATE METHODS

    /*
     * 
     * 
     */
    private HTTPRedirect()
    { 
    }

    #endregion


    #region  PUBLIC METHODS

    /*
     * 
     * 
     */
    public static HTTPRedirect getInstance()
    {
      if (cInstance == null)
        cInstance = new HTTPRedirect();

      return (cInstance);
    }



    /*
     * 
     * 
     */
    public void processRequest(Stream pServerStream, String pRedirectURL, Hashtable pHeaders)
    {
      String lOutput = String.Format("HTTP/1.1 301 Found\nLocation: http://{0}\r\n\r\n", pRedirectURL);
      byte[] lRedirectBytesArray = Encoding.ASCII.GetBytes(lOutput); // String.Format("HTTP/1.1 301 Found\nLocation: http://{0}\r\n\r\n", pRedirectURL));
      int lTotalBytes = lRedirectBytesArray.Length;

      Logging.LogMessage(String.Format("HTTPRedirect.processRequest() : {0}", lOutput), Logging.Level.DEBUG);

      /*
       * Print headers
       */
      if (Config.LogLevel == Logging.Level.DEBUG && pHeaders != null && pHeaders.Count > 0)
        foreach (String lKey in pHeaders.Keys)
            Logging.LogMessage(String.Format("HTTPRedirect.processRequest() : {0}: {1}", lKey, pHeaders[lKey]), Logging.Level.DEBUG);

      /*
       * Send back redirect code
       */
      pServerStream.Write(lRedirectBytesArray, 0, lTotalBytes);
      pServerStream.Flush();
    }

    #endregion

  }
}
