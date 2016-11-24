using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Collections;
using System.Text.RegularExpressions;
using System.Net.Security;
using System.Net.Sockets;


namespace HTTPReverseProxyServer
{

    public class RequestObj : ICloneable
    {

        #region MEMBERS

        // Client TCP connection
        public String SrcMAC;
        public String SrcIP;
        public String SrcPort;
        public TcpClient TCPClientConnection;

        // Client HTTP connection
        public int ClientRequestContentLen;
        public String Method;
        public String Host;
        public String Path;
        public String Scheme;

        public Hashtable ClientRequestHeaders;
        public StreamReader ClientStreamReader;
        public Stream ClientStream;

        // Server HTTP connection
        public List<Tuple<String, String>> ServerResponseHeaders;
        public HttpWebRequest ServerWebRequest;
        public HttpWebResponse ServerWebResponse;

        // ...
        public int Counter;
        public String HTTPLogData;
        private String DefaultHost;
        
        #endregion


        #region PROPERTIES

        #endregion


        #region PUBLIC METHODS

        /*
         * 
         * 
         */
        public RequestObj(String pDefaultHost)
        {
            this.DefaultHost = pDefaultHost;
            this.ClientRequestContentLen = 0;
            this.ClientRequestHeaders = new Hashtable();
            this.ClientStreamReader = null;
            this.ClientStream = null;
            this.Method = String.Empty;
            this.Scheme = "http";
            this.Host = String.Empty;
            this.Path = String.Empty;
            this.HTTPLogData = String.Empty;
            this.ServerResponseHeaders = new List<Tuple<String, String>>();
            this.ServerWebRequest = null;
            this.ServerWebResponse = null;
        }


        /*
         * 
         * 
         */
        public void parseRequestString(String pRequestString)
        {
            String[] lReqSplitBuffer = pRequestString.Split(new char[] { ' ' }, 3);
            this.Method = lReqSplitBuffer[0];
            this.Path = lReqSplitBuffer[1];
            if (!this.Path.StartsWith("/"))
                this.Path = String.Format("/{0}", this.Path);

            this.HTTPLogData = pRequestString.Trim();
        }
        

        /*
         * 
         * 
         */
        public String getRequestedURL()
        {
            String lRequestURL = String.Empty;

            if (!String.IsNullOrEmpty(this.Host))
                lRequestURL = String.Format("{0}://{1}{2}", this.Scheme, this.Host, this.Path);
            else
                lRequestURL = String.Format("{0}://{1}{2}", this.Scheme, this.DefaultHost, this.Path);

            return lRequestURL;
        }


        /*
         * 
         * 
         */
        public object Clone()
        {
            return this.MemberwiseClone();
        }

        #endregion

    }


  class HTTPAccounts
  {

    #region MEMBERS

    private static readonly int BUFFER_SIZE = 8192;
    private static readonly char[] cSemiSplit = new char[] { ';' };
    private static readonly Regex cCookieSplitRegEx = new Regex(@",(?! )");

    #endregion



    #region PUBLIC METHODS

    /*
     * 
     * 
     */
    public HTTPAccounts()
    { 
    }


    /*
     * 
     * 
     */
    public void sendServerResponse2Client(RequestObj pRequestObj)
    {
      StreamWriter lMyResponseWriter = null;
      Stream lResponseStream = null;
      Byte[] lBuffer;
      int lBytesRead = 0;


      try
      {
        lMyResponseWriter = new StreamWriter(pRequestObj.ClientStream); 
        lResponseStream = pRequestObj.ServerWebResponse.GetResponseStream();

        /*
         * 1. Send "server response string" to client
         */
        String lOut = String.Format("HTTP/1.0 {0} {1}\n", (Int32) pRequestObj.ServerWebResponse.StatusCode, pRequestObj.ServerWebResponse.StatusDescription);
        byte[] lOutByteArray = Encoding.ASCII.GetBytes(lOut);
        pRequestObj.ClientStream.Write(lOutByteArray, 0, lOutByteArray.Length);
        Logging.LogMessage(String.Format("HTTPAccounts.sendServerResponse2Client(2Client) : {0}", lOut), Logging.Level.DEBUG, pRequestObj.Counter);



        /*
         * 2. Send "server response headers" to client
         */

        foreach (Tuple<String, String> lHeaderTmp in pRequestObj.ServerResponseHeaders)
        {
            byte[] lTmp = Encoding.ASCII.GetBytes(String.Format("{0}: {1}\n", lHeaderTmp.Item1, lHeaderTmp.Item2));
            pRequestObj.ClientStream.Write(lTmp, 0, lTmp.Length);
            Logging.LogMessage(String.Format("HTTPAccounts.sendServerResponse2Client(2Client:HEADER) : {0}: {1}", lHeaderTmp.Item1, lHeaderTmp.Item2), Logging.Level.DEBUG, pRequestObj.Counter);          
        }

        pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes("\n"), 0 , 1);

        if (pRequestObj.ServerWebResponse.ContentLength > 0)
          lBuffer = new Byte[pRequestObj.ServerWebResponse.ContentLength];
        else
          lBuffer = new Byte[BUFFER_SIZE];


        /*
         * 3. Send "server response data section" to client
         */
        int lDataVolume = 0;
        while ((lBytesRead = lResponseStream.Read(lBuffer, 0, lBuffer.Length)) > 0)
        {
          Logging.LogMessage(String.Format("HTTPAccounts.sendServerResponse2Client(DATA) : Sending data from ... Server -> Client ({0} bytes)", lBytesRead), Logging.Level.DEBUG, pRequestObj.Counter);
          lDataVolume += lBytesRead;
          pRequestObj.ClientStream.Write(lBuffer, 0, lBytesRead);
        } // while ((lByte...


        Logging.LogMessage(String.Format("HTTPAccounts.sendServerResponse2Client(DATA) : Total data sent from    Server -> Client : {0}", lDataVolume), Logging.Level.DEBUG, pRequestObj.Counter);

        lResponseStream.Close();
        pRequestObj.ClientStream.Flush();
      }
      catch (Exception lEx)
      {
          Logging.LogMessage(String.Format("HTTPAccounts.sendServerResponse2Client(EXCEPTION) : {0}\n{1}", lEx.Message, lEx.StackTrace), Logging.Level.ERROR, pRequestObj.Counter);
      }
      finally
      {
        if (lResponseStream != null)
          lResponseStream.Close();

        if (lMyResponseWriter != null)
          lMyResponseWriter.Close();
      }
    }


    /*
     * 
     * 
     */
    public void sendRequestAndParseServerResponseHeader(RequestObj pRequestObj)
    {
        char[] lPostBuffer;
        int lPOSTBytesRead = 0;
        int lTotalBytesRead = 0;
        StreamWriter lSW = null;
        String lTmpStr = String.Empty;
        String lTmpBuf = String.Empty;
        String lPOSTData = String.Empty;

        Logging.LogMessage(String.Format("HTTPClientRequest.sendRequestAndParseServerResponseHeader() : Requesting URL \"{0}\"", pRequestObj.getRequestedURL()), Logging.Level.DEBUG, pRequestObj.Counter);
                  

        /*
         * Setup the http request to send on behalf of the actual client.
         * Neutralize the server certificate validation.
         */
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };   

        pRequestObj.ServerWebRequest = (HttpWebRequest) HttpWebRequest.Create(pRequestObj.getRequestedURL());
        pRequestObj.ServerWebRequest.Method = pRequestObj.Method;
        pRequestObj.ServerWebRequest.ProtocolVersion = System.Net.HttpVersion.Version10;
        pRequestObj.ServerWebRequest.Timeout = 10000;
        pRequestObj.ServerWebRequest.Proxy = null;
        pRequestObj.ServerWebRequest.KeepAlive = false;
        pRequestObj.ServerWebRequest.AllowAutoRedirect = false;
        pRequestObj.ServerWebRequest.AutomaticDecompression = DecompressionMethods.None;

        this.SetClientRequestHTTPHeaders(pRequestObj.ClientRequestHeaders, ref pRequestObj.ServerWebRequest);



        /*
         * Send POST data to remote server
         */
        if (pRequestObj.Method.ToUpper() == "POST")
        {
            lPostBuffer = new char[pRequestObj.ClientRequestContentLen];
            lTotalBytesRead = 0;
            lSW = new StreamWriter(pRequestObj.ServerWebRequest.GetRequestStream());

            while (lTotalBytesRead < pRequestObj.ClientRequestContentLen && (lPOSTBytesRead = pRequestObj.ClientStreamReader.ReadBlock(lPostBuffer, 0, pRequestObj.ClientRequestContentLen)) > 0)
            {
                lTmpStr = new string(lPostBuffer);

                lTotalBytesRead += lPOSTBytesRead;
                lSW.Write(lPostBuffer, 0, lPOSTBytesRead);

                lTmpBuf += lTmpStr;
            } // while (lTotalBytes...

            if (lSW != null)
                lSW.Close();

            if (lTmpBuf != null && lTmpBuf.Length > 0)
                lPOSTData = lTmpBuf.ToString();
        } // if (lMethod.To...
        

        // Read and parse server response headers
        // Build HTTP request data string

        pRequestObj.ServerWebResponse = (HttpWebResponse) pRequestObj.ServerWebRequest.GetResponse();
        this.ProcessServerResponseHeaders(pRequestObj);
             
        // Create Data log string        
        pRequestObj.HTTPLogData = String.Empty;
        foreach (String lKey in pRequestObj.ServerWebResponse.Headers.AllKeys)
            pRequestObj.HTTPLogData += String.Format("..{0}: {1}", lKey, pRequestObj.ServerWebRequest.Headers[lKey]);

        pRequestObj.HTTPLogData += String.Format("....{0}", lPOSTData);
    }



    /*
     * 
     * 
     */
    public void SetClientRequestHTTPHeaders(Hashtable pHeaders, ref HttpWebRequest pWebReq)
    {
      if (pHeaders != null && pHeaders.Count > 0)
      {
        foreach (String lKey in pHeaders.Keys)
        {
          switch (lKey.ToLower())
          {
            case "host":
              pWebReq.Host = pHeaders[lKey].ToString();
              break;
            case "user-agent":
              pWebReq.UserAgent = pHeaders[lKey].ToString();
              break;
            case "accept":
              pWebReq.Accept = pHeaders[lKey].ToString();
              break;
            case "referer":
              pWebReq.Referer = pHeaders[lKey].ToString();
              break;
            case "cookie":
              pWebReq.Headers["Cookie"] = pHeaders[lKey].ToString();
              break;
            case "proxy-connection":
            case "connection":
            case "keep-alive":
              //ignore these
              break;
            //            case "content-length":
            //              int.TryParse(lHeader[1], out lContentLen);
            //              break;
            case "content-type":
              pWebReq.ContentType = pHeaders[lKey].ToString();
              break;
            case "if-modified-since":
              String[] sb = pHeaders[lKey].ToString().Trim().Split(cSemiSplit);
              DateTime d;
              if (DateTime.TryParse(sb[0], out d))
              {
                pWebReq.IfModifiedSince = d;
              }
              break;
            default:
              try
              {
                pWebReq.Headers.Add(lKey, pHeaders[lKey].ToString());
              }
              catch (Exception lEx)
              {
                  Logging.LogMessage(String.Format("HTTPAccounts.SetClientRequestHTTPHeaders(EXCEPTION) : {0}", lEx.Message), Logging.Level.ERROR, 0);
              }
              break;
          }
        } // foreach (Strin...
      } // if (pHeaders !=...
    }
      


    /*
     * 
     * 
     */
    private void ProcessServerResponseHeaders(RequestObj pRequestObj)
    {
      String lValue = null;
      String header = null;

      pRequestObj.ServerResponseHeaders.Clear();

      foreach (String lTmp in pRequestObj.ServerWebResponse.Headers.Keys)
      {
        if (lTmp.ToLower() == "set-cookie")
        {
            header = lTmp;
            lValue = pRequestObj.ServerWebResponse.Headers[lTmp];
        }
        else if (lTmp.ToLower() == "strict-transport-security" && Config.IgnoreHSTS)
        {
            Logging.LogMessage(String.Format("HTTPAccounts.ProcessServerResponseHeaders() : Strict-Transport-Security header removed"), Logging.Level.INFO, pRequestObj.Counter);
            HSTSCache.Instance.addElement(pRequestObj.Host);
        }
        else
            pRequestObj.ServerResponseHeaders.Add(new Tuple<String, String>(lTmp, pRequestObj.ServerWebResponse.Headers[lTmp]));
      } // foreach (St...


      if (!String.IsNullOrWhiteSpace(lValue))
      {
        pRequestObj.ServerWebResponse.Headers.Remove(header);
        String[] lCookies = cCookieSplitRegEx.Split(lValue);

        foreach (String lCookie in lCookies)
            pRequestObj.ServerResponseHeaders.Add(new Tuple<String, String>("Set-Cookie", lCookie));
      } // if (!Strin...        
    }


    #endregion

  }
}
