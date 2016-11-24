using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Collections;
using System.Net.Sockets;
using System.Text.RegularExpressions;


namespace HTTPReverseProxyServer
{
    public class HTTPClientRequest
    {

        #region MEMBERS  

        HTTPAccounts cServerRequestHandler;

        #endregion


        #region PUBLIC METHODS

        public HTTPClientRequest()
        {
            cServerRequestHandler = new HTTPAccounts();
        }


        /*
         * 
         * 
         */
        public void HandleClientRequest(RequestObj pRequestObj)
        {
            String lHTTPRequestString = pRequestObj.ClientStreamReader.ReadLine();

            if (String.IsNullOrEmpty(lHTTPRequestString))
                throw new Exception("Client request stream corrupted.");

            // Read the request headers from the client and copy them to the request settings
            // Set values : METHOD scheme://host/Path
            Logging.LogMessage(String.Format("HTTPClientRequest.HandleClientRequest() : HTTP Request string: \"{0}\"", lHTTPRequestString), Logging.Level.DEBUG, pRequestObj.Counter);
            pRequestObj.parseRequestString(lHTTPRequestString);
            this.ReadRequestHeadersFromClient(pRequestObj);

            pRequestObj.Host = pRequestObj.ClientRequestHeaders["host"].ToString();
            pRequestObj.Scheme = "http";


            /*
             * Verify if request parameters are correct.
             */
            if (!Regex.Match(pRequestObj.Method.ToLower(), @"^\s*(get|put|post|head|delete|trace|options|connect)\s*$").Success)
                throw new WebException("Client request contains an unsupproted request method");
            

            String lRequestedURL = String.Format("{0}://{1}{2}", pRequestObj.Scheme, pRequestObj.Host, pRequestObj.Path);



            /*
             *   If HTTP request was redirected to an other URL in a previous request
             *   replace current request with the redirect location
             */
            if (RedirectCache.Instance.NeedsRequestBeMapped(lRequestedURL))
            {
                Logging.LogMessage(String.Format("HTTPClientRequest.HandleClientRequest() : REDIRECT(301/302) from \"{0}\" to \"{1}\"", lRequestedURL, RedirectCache.Instance.GetElement(lRequestedURL).URL), Logging.Level.INFO, pRequestObj.Counter);

                // DO SSL STRIPPING THINGS HERE !!!!
                // Replace the URL by the URL saved in the cache ...
                RedirectHost lTmpHost = RedirectCache.Instance.GetElement(pRequestObj.getRequestedURL());

                pRequestObj.Method = "GET";
                pRequestObj.Scheme = lTmpHost.Scheme;
                pRequestObj.Host = lTmpHost.Host;
                pRequestObj.Path = lTmpHost.Path;

                lTmpHost.IncCounter();
            } // if (RedirectCac...


            /*
             * If HTTP request was answered with an HSTS server response header
             * conduct an HTTPS request instead of HTTP 
             */
            else if (HSTSCache.Instance.GetElement(pRequestObj.Host) != null)
            {
                Logging.LogMessage(String.Format("HTTPClientRequest.HandleClientRequest() : HSTS protocol replacement : http://{0} -> https://{0} \n", pRequestObj.Host), Logging.Level.DEBUG, pRequestObj.Counter);
                pRequestObj.Scheme = "https";
            } // if (HSTSCache...


            try
            {
                /*
                 * Forward request according to the URL defined
                 * in the command line parameter.
                 */
                if (!String.IsNullOrEmpty(Config.RedirectToURL) && pRequestObj.Method.ToLower() == "get")
                    HTTPRedirect.getInstance().processRequest(pRequestObj.ClientStream, Config.RedirectToURL, pRequestObj.ClientRequestHeaders);            
                else
                    this.DoHttpProcessing(pRequestObj);
            }
            catch (WebException lEx)
            {
                /*
                 * 1. Sending server response
                 */
                var lResponse = lEx.Response as HttpWebResponse;
                if (lResponse != null && lResponse.StatusCode != HttpStatusCode.OK)
                {
                    String ErrorCode = String.Format("HTTP/{0} {1} {2}\n", lResponse.ProtocolVersion, (int)lResponse.StatusCode, lResponse.StatusDescription);
                    pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes(ErrorCode), 0, ErrorCode.Length);
                }
                else
                {
                    String ErrorCode = String.Format("HTTP/1.1 500 Internal server error\n");
                    pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes(ErrorCode), 0, ErrorCode.Length);
                } // if (lRespon...

                /*
                 * 2. Sending server response headers
                 */
                if (lEx.Response != null && lEx.Response.Headers != null && lEx.Response.Headers.Count > 0)
                {
                    foreach (String la in lEx.Response.Headers.AllKeys)
                    {
                        String lResp = String.Format("{0}: {1}\n", la, lEx.Response.Headers[la]);
                        pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes(lResp), 0, lResp.Length);
                    } // foreach (Stri...
                } // if (lEx.Resp ...

                pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes("\n"), 0, 1);

                /*
                 * 3. Sending server response body
                 */
                try
                {
                    var resp = new StreamReader(lEx.Response.GetResponseStream()).ReadToEnd();
                    pRequestObj.ClientStream.Write(Encoding.ASCII.GetBytes(resp), 0, resp.Length);
                }
                catch (Exception lEx2)
                {
                    Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing(EXCEPTION2) : {0} -> {1} \n{2}", pRequestObj.getRequestedURL(), lEx.Message, lEx.StackTrace), Logging.Level.ERROR, pRequestObj.Counter);
                }
            }
            catch (Exception lEx)
            {
                Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing(EXCEPTION) : {0} -> {1} \n{2}", pRequestObj.getRequestedURL(), lEx.Message, lEx.StackTrace), Logging.Level.ERROR, pRequestObj.Counter);
            }
            finally
            {
                if (pRequestObj.ClientStreamReader != null)
                    pRequestObj.ClientStreamReader.Close();

                if (pRequestObj.ClientStream != null)
                    pRequestObj.ClientStream.Close();

                if (pRequestObj.ServerWebResponse != null)
                    pRequestObj.ServerWebResponse.Close(); 
            }
        }



        /*
         * 
         * 
         */
        public void DoHttpProcessing(RequestObj pRequestObj)
        {
          String lHTTPRequestString = String.Empty;

          Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : Client {0} requested URL : \"{1}\"", pRequestObj.SrcIP, pRequestObj.getRequestedURL()), Logging.Level.INFO, pRequestObj.Counter);


          /*
           * Process HTTP request. 
           * 1. Detect HTTP Redirect requests
           * 2. Cache new HTTP Redirect locations
           * 3. Recognize incoming client requests that need to be SSL-Stripped
           * 4. Process reqular HTTP requests
           * 
           * 
           * 
           * 1. Client requests a SSL-Stripping page found in the RedirectCache 
           *    The requested URL previously was detected as a "HTTP 301/302 Redirect" to a SSL/TLS protected web site.
           *    Skip the HTTP/Redirect part and directly proxy the data from the SSL/TLS protected website to the user.
           *    
           *    Format : SCHEME://HOST
           */




          // 2. Send client request URL to server and parse response headers
          pRequestObj.ServerResponseHeaders.Clear();
          cServerRequestHandler.sendRequestAndParseServerResponseHeader(pRequestObj);

          RedirectType lRedirType = this.DetermineRedirectType(pRequestObj);



          /*
           * The HTTP client request triggers a regular HTML data response.
           * 1. Transfer the server response (Server response string, headers, data)
           */
          if (lRedirType == RedirectType.Http2http2XX)
          {
            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Http2http2XX \"{0}\" -> \"-\"", pRequestObj.getRequestedURL()), Logging.Level.DEBUG, pRequestObj.Counter);


          /*
           * The HTTP client request triggers a request to a HTTP URL
           * 1. Transfer the server response (Server response string, headers, data)
           */
          }
          else if (lRedirType == RedirectType.Http2Http3XX)
          {
            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Http2Http3XX \"{0}\" -> \"{1}\"", pRequestObj.getRequestedURL(), pRequestObj.ServerWebResponse.GetResponseHeader("Location")), Logging.Level.DEBUG, pRequestObj.Counter);


          /*
           * The HTTP client request triggers a request to a HTTP URL
           * 1. Cache the HTTP/HTTPS mapping
           * 2. Replace the "https" scheme in the redirect location by "http"
           * 3. Transfer the server response (Server response string, headers, data)
           */
          }
          else if (lRedirType == RedirectType.Http2Https3XXDifferentURL)
          {
              Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Http2Http3XXDifferentURL \"{0}\" -> \"{1}\"", pRequestObj.getRequestedURL(), pRequestObj.ServerWebResponse.GetResponseHeader("Location")), Logging.Level.DEBUG, pRequestObj.Counter);
              this.SendRequest2RedirectLocation(pRequestObj);



          /*
           * 1. Resend the same request again to the same URL but with "https" scheme instead of "http"
           * 2. Transfer the server response (Server response string, headers, data)
           */
          }
          else if (lRedirType == RedirectType.Http2Https3XXSameURL)
          {
            // Save redirect information in cache

            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Http2Https3XXSameURL \"{0}\" -> \"{1}\"", pRequestObj.getRequestedURL(), pRequestObj.ServerWebResponse.GetResponseHeader("Location")), Logging.Level.DEBUG, pRequestObj.Counter);
            this.SendRequest2RedirectLocation(pRequestObj);
              

          /*
          * The HTTP client request triggers a regular HTML data response.
          * 1. Transfer the server response (Server response string, headers, data)
          */
          }
          else if (lRedirType == RedirectType.Https2Http2XX)
          {    
            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Https2Http2XX"), Logging.Level.DEBUG, pRequestObj.Counter);



          /*
           * This should never happen!! 
           * We're lost in an endless loop!
           */
          }
          else if (lRedirType == RedirectType.Https2Https3XXSameURL)
          {
              Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Https2HttpsRedirectSameURL\n\n\n\nHOOOOONK\n\n\n"), Logging.Level.DEBUG, pRequestObj.Counter);

              String lLogData = String.Format("HTTPClientRequest.DoHttpProcessing() : \"{0}\" -> \"{1}\"", pRequestObj.getRequestedURL(), pRequestObj.ServerResponseHeaders.Find(item => item.Item1 == "Location"));

              Logging.LogMessage(lLogData, Logging.Level.DEBUG);

          }
          else if (lRedirType == RedirectType.Https2Https3XXDifferentURL)
          {
              Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Https2HttpsRedirectDiffrentURL"), Logging.Level.DEBUG, pRequestObj.Counter);

              /*
               * The HTTP client request triggers a request to a HTTP URL
               * 1. Cache the HTTP/HTTPS mapping
               * 2. Replace the "https" scheme in the redirect location by "http"
               * 3. Transfer the server response (Server response string, headers, data)
               */
              Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Https2Https3XXDifferentURL \"{0}\" -> \"{1}\"", pRequestObj.getRequestedURL(), pRequestObj.ServerWebResponse.GetResponseHeader("Location")), Logging.Level.DEBUG, pRequestObj.Counter);
              this.SendRequest2RedirectLocation(pRequestObj);


          /*
           * This should never happen!!
           * No clue what to do at this point!
           */
          }
          else
          {
            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE definition error for URL \"{0}\" ", pRequestObj.getRequestedURL()), Logging.Level.DEBUG, pRequestObj.Counter);
          }

          cServerRequestHandler.sendServerResponse2Client(pRequestObj);

          String lPipeData = lPipeData = String.Format("HTTPClientRequest.DoHttpProcessing() : TCP||{0}||{1}||{2}||{3}||{4}||{5}\r\n", pRequestObj.SrcMAC, pRequestObj.SrcIP, pRequestObj.SrcPort, Config.RemoteHostIP, Config.RemoteHostPort, pRequestObj.HTTPLogData);
          Program.WriteToPipe(lPipeData);
        }


        /*
         * 
         * 
         */
        private void SendRequest2RedirectLocation(RequestObj pRequestObj)
        {
            String lRedirectLocationHTTPS = pRequestObj.ServerWebResponse.GetResponseHeader("Location");
            String lRedirectLocationHTTP = pRequestObj.getRequestedURL();
            try { RedirectCache.Instance.addElement(lRedirectLocationHTTP, lRedirectLocationHTTPS); } catch { }

            Logging.LogMessage(String.Format("HTTPClientRequest.DoHttpProcessing() : TYPE Http2Https3XXSameURL \"{0}\" -> \"{1}\"", lRedirectLocationHTTP, lRedirectLocationHTTPS), Logging.Level.DEBUG, pRequestObj.Counter);


            // Close the preceding WebResponse (stream & headers)
            pRequestObj.ServerResponseHeaders.Clear();

            if (pRequestObj.ServerWebResponse != null)
                pRequestObj.ServerWebResponse.Close();

            RequestObj lTmpReqObj = (RequestObj)pRequestObj.Clone();
            Uri lTmpUri = new Uri(lRedirectLocationHTTPS);

            lTmpReqObj.Scheme = lTmpUri.Scheme;
            lTmpReqObj.Host = lTmpUri.Host;
            lTmpReqObj.Path = lTmpUri.PathAndQuery;
            if (lTmpReqObj.ClientRequestHeaders.ContainsKey("host"))
            {
                lTmpReqObj.ClientRequestHeaders.Remove("host");
                lTmpReqObj.ClientRequestHeaders.Add("host", lTmpReqObj.Host);
            }
            lTmpReqObj.Counter++;


            this.DoHttpProcessing(lTmpReqObj);

            pRequestObj.ServerWebResponse = lTmpReqObj.ServerWebResponse;
            pRequestObj.ServerResponseHeaders = lTmpReqObj.ServerResponseHeaders;
        }



        /*
         * 
         * 
         */
        private void ReadRequestHeadersFromClient(RequestObj pRequestObj)
        {
            String lHTTPHeader;
            int lContentLen = 0;


            do
            {
                lHTTPHeader = pRequestObj.ClientStreamReader.ReadLine();

                if (String.IsNullOrEmpty(lHTTPHeader))
                    break;

                String[] lHeader = lHTTPHeader.Split(new string[] { ": " }, 2, StringSplitOptions.None);
                Logging.LogMessage(String.Format("HTTPClientRequest.ReadRequestHeadersFromClient() : {0}: {1}", lHeader[0], lHeader[1]), Logging.Level.DEBUG, pRequestObj.Counter);


                switch (lHeader[0].ToLower())
                {
                    case "host":
                        pRequestObj.ClientRequestHeaders.Add("host", lHeader[1]);
                        break;
                    case "user-agent":
                        pRequestObj.ClientRequestHeaders.Add("user-agent", lHeader[1]);
                        break;
                    case "accept":
                        pRequestObj.ClientRequestHeaders.Add("accept", lHeader[1]);
                        break;
                    case "referer":
                        pRequestObj.ClientRequestHeaders.Add("referer", lHeader[1]);
                        break;
                    case "cookie":
                        pRequestObj.ClientRequestHeaders.Add("cookie", lHeader[1]);
                        break;
                    case "proxy-connection":
                    case "connection":
                    case "keep-alive":
                        //ignore these
                        break;
                    case "content-length":
                        int.TryParse(lHeader[1], out lContentLen);
                        pRequestObj.ClientRequestContentLen = lContentLen;
                        pRequestObj.ClientRequestHeaders.Add("content-length", lHeader[1]);
                        break;
                    case "content-type":
                        pRequestObj.ClientRequestHeaders.Add("content-type", lHeader[1]);
                        break;
                    case "if-modified-since":
                        String[] sb = lHeader[1].Trim().Split(new char[] { ';' });
                        DateTime d;
                        if (DateTime.TryParse(sb[0], out d))
                        {
                            pRequestObj.ClientRequestHeaders.Add("if-modified-since", lHeader[1]);
                        }
                        break;
                    default:
                        try
                        {
                            pRequestObj.ClientRequestHeaders.Add(lHeader[0], lHeader[1]);
                        }
                        catch (Exception lEx)
                        {
                            Logging.LogMessage(String.Format("HTTPClientRequest.ReadRequestHeadersFromClient(EXCEPTION) : {0}", lEx.Message), Logging.Level.ERROR, pRequestObj.Counter);
                        }
                        break;
                } // switch (....
            }
            while (!String.IsNullOrWhiteSpace(lHTTPHeader));
        }

        #endregion


        #region PRIVATE METHODS

        private enum RedirectType:int 
        {
            Http2http2XX = 0,
            Http2Http3XX = 1,
            Http2Https3XXSameURL = 2,
            Http2Https3XXDifferentURL = 3,
            Https2Http2XX = 4,
            Https2Https3XXSameURL = 5,
            Https2Https3XXDifferentURL = 6,
            Error = 7
        }



        private RedirectType DetermineRedirectType(RequestObj pRequestObj)
        {
            String lRedirectHeader = String.Empty;
            try { lRedirectHeader = pRequestObj.ServerResponseHeaders.FirstOrDefault(hdr => hdr.Item1.ToLower().Contains("location")).Item2; } catch (Exception) {}
            Boolean lHasRedirectHeader = String.IsNullOrEmpty(lRedirectHeader) ? false : true;
            Uri lTmpUri = lHasRedirectHeader ? new Uri(lRedirectHeader) : null;

            String lRequestScheme = pRequestObj.Scheme;
            String lRequestURL = String.Format("{0}{1}", pRequestObj.Host, pRequestObj.Path);
            String lRedirectURL = lHasRedirectHeader ? (String.Format("{0}{1}", lTmpUri.Host, lTmpUri.PathAndQuery)) : String.Empty;
            String lRedirectScheme = lHasRedirectHeader ? lTmpUri.Scheme.ToLower() : String.Empty;

            Logging.LogMessage(String.Format("HTTPClientRequest.DetermineRedirectType() : \"{0}://{1}\" -> Redirected:{2} to \"{3}://{4}\"", lRequestScheme, lRequestURL, lHasRedirectHeader, lRedirectScheme, lRedirectURL), Logging.Level.DEBUG, pRequestObj.Counter);

            if (lRequestScheme == "http" && lHasRedirectHeader == false)
                return RedirectType.Http2http2XX;
            else if (lRequestScheme == "http" && lHasRedirectHeader == true && lRedirectScheme == "http")
                return RedirectType.Http2Http3XX;
            else if (lRequestScheme == "http" && lHasRedirectHeader == true && lRedirectScheme == "https" && lRequestURL != lRedirectURL)
                return RedirectType.Http2Https3XXDifferentURL;
            else if (lRequestScheme == "http" && lHasRedirectHeader == true && lRedirectScheme == "https" && lRequestURL == lRedirectURL)
                return RedirectType.Http2Https3XXSameURL;

            else if (lRequestScheme == "https" && lHasRedirectHeader == false)
                return RedirectType.Https2Http2XX;
            else if (lRequestScheme == "https" && lHasRedirectHeader == true && lRedirectScheme == "https" && lRequestURL != lRedirectURL)
                return RedirectType.Https2Https3XXDifferentURL;
            else if (lRequestScheme == "https" && lHasRedirectHeader == true && lRedirectScheme == "https" && lRequestURL == lRedirectURL)
                return RedirectType.Https2Https3XXSameURL;

            else
                return RedirectType.Error;
        }


        #endregion


    }
}
