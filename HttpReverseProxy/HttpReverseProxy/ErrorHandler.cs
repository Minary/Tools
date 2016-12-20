namespace HttpReverseProxy
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Class.Client;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Net;
  using System.Text;


  public class ClientErrorHandler
  {

    #region MEMBERS

    private Dictionary<HttpStatusCode, HttpStatusDetails> statusDescription = new Dictionary<HttpStatusCode, HttpStatusDetails>()
    {
      { HttpStatusCode.BadRequest, new HttpStatusDetails(400, "Bad Request", "The server cannot handle the request due to an apparent client error.") },
      { HttpStatusCode.NotFound, new HttpStatusDetails(404, "Not Found", "The requested URL is either incomplete or could not be found.") },
      { HttpStatusCode.MethodNotAllowed, new HttpStatusDetails(405, "Method Not Allowed", "The request method is not supported for the requested resource.") },
      { HttpStatusCode.HttpVersionNotSupported, new HttpStatusDetails(505, "HTTP Version Not Supported", "The server does not support the HTTP protocol version used in the request.") },
      { HttpStatusCode.InternalServerError, new HttpStatusDetails(500, "Internal Server Error", "Internal Server Error.") }
    };

    #endregion


    #region PUBLIC

    /// <summary>
    /// Send custom HttpReverseProxyServer error message to the client system.
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="cnex"></param>
    public void SendErrorMessage2Client(RequestObj requestObj, ClientNotificationException cnex)
    {
      string httpServerResponseStatus = string.Format("HTTP/1.1 {0} {1}", this.statusDescription[HttpStatusCode.InternalServerError].Code, this.statusDescription[HttpStatusCode.InternalServerError].Title);
      string message = message = this.statusDescription[HttpStatusCode.InternalServerError].Description;

      if (cnex.Data.Contains(StatusCodeLabel.StatusCode))
      {
        HttpStatusCode code = (HttpStatusCode)cnex.Data[StatusCodeLabel.StatusCode];
        httpServerResponseStatus = string.Format("HTTP/1.1 {0} {1}", this.statusDescription[code].Code, this.statusDescription[code].Title);
        message = this.statusDescription[code].Description;
      }

      string[] serverHeaders = new string[] { httpServerResponseStatus, "Content-Type: text/html", "Connection: close", string.Format("Content-Length: {0}", message.Length) };

      // Send headers to client
      foreach (string tmpHeader in serverHeaders)
      {
        this.SendStringToClient(requestObj.ClientRequestObj.ClientBinaryWriter, tmpHeader, true);
      }

      // Send ...
      this.SendStringToClient(requestObj.ClientRequestObj.ClientBinaryWriter, "\n", false);

      // Send message to client
      this.SendStringToClient(requestObj.ClientRequestObj.ClientBinaryWriter, message, false);
    }



    /// <summary>
    /// Send error message originating from actual HTTP server to the client system.
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="cnex"></param>
    public void ProcessWebException(RequestObj requestObj, WebException webEx)
    {

      // 1. Send cRemoteSocket response
      var response = webEx.Response as HttpWebResponse;
      if (response != null && response.StatusCode != HttpStatusCode.OK)
      {
        string errorCode = string.Format("HTTP/{0} {1} {2}\n", response.ProtocolVersion, (int)response.StatusCode, response.StatusDescription);
        ////        requestObj.ClientRequestNetworkStream.Write(Encoding.ASCII.GetBytes(errorCode), 0, errorCode.Length);
        requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(errorCode), 0, errorCode.Length);
      }
      else
      {
        string errorCode = string.Format("HTTP/1.1 500 Internal cRemoteSocket error\n");
        requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(errorCode), 0, errorCode.Length);
      }

      // 2. Sending cRemoteSocket response headers
      if (webEx.Response != null && webEx.Response.Headers != null && webEx.Response.Headers.Count > 0)
      {
        foreach (string tmpKey in webEx.Response.Headers.AllKeys)
        {
          string httpResponseString = string.Format("{0}: {1}\n", tmpKey, webEx.Response.Headers[tmpKey]);
          requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(httpResponseString), 0, httpResponseString.Length);
        }
      }

      requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes("\n"), 0, 1);

      // 3. Sending cRemoteSocket response body
      try
      {
        var resp = new StreamReader(webEx.Response.GetResponseStream()).ReadToEnd();
        requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(resp), 0, resp.Length);
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Logging.Level.ERROR, "IncomingClientRequest.ProcessWebException(EXCEPTION2) : {0} -> {1} \n{2}", requestObj.ClientRequestObj.GetRequestedUrl(), ex.Message, ex.StackTrace);
      }
    }

    #endregion


    #region PRIVATE

    /// <summary>
    /// Convert string message to byte array and send it to the client system.
    /// </summary>
    /// <param name="clientStream"></param>
    /// <param name="message"></param>
    /// <param name="addTrailingNewLine"></param>
    private void SendStringToClient(BinaryWriter clientStream, string message, bool addTrailingNewLine)
    {
      if (addTrailingNewLine)
      {
        message += "\n";
      }

      byte[] messageBytes = Encoding.UTF8.GetBytes(message);
      clientStream.Write(messageBytes, 0, messageBytes.Length);
    }

    #endregion

  }
}
