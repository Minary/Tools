namespace HttpReverseProxy
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
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
      var tmpStatusCode = this.statusDescription[HttpStatusCode.InternalServerError].Code;
      var tmpStatusTitle = this.statusDescription[HttpStatusCode.InternalServerError].Title;
      var httpServerResponseStatus = $"HTTP/1.1 {tmpStatusCode} {tmpStatusTitle}";
      var message = this.statusDescription[HttpStatusCode.InternalServerError].Description;

      if (cnex.Data.Contains(StatusCodeLabel.StatusCode))
      {
        HttpStatusCode code = (HttpStatusCode)cnex.Data[StatusCodeLabel.StatusCode];
        var tmpStatusCode2 = this.statusDescription[code].Code;
        var tmpStatusTitle2 = this.statusDescription[code].Title;
        httpServerResponseStatus = $"HTTP/1.1 {tmpStatusCode2} {tmpStatusTitle2}";
        message = this.statusDescription[code].Description;
      }

      var serverHeaders = new string[] { httpServerResponseStatus, "Content-Type: text/html", "Connection: close", $"Content-Length: {message.Length}" };

      // Send headers to client
      foreach (var tmpHeader in serverHeaders)
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
      if (response?.StatusCode != HttpStatusCode.OK)
      {
        var errorCode = $"HTTP/{response.ProtocolVersion} {(int)response.StatusCode} {response.StatusDescription}\n";
        requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(errorCode), 0, errorCode.Length);
      }
      else
      {
        var errorCode = "HTTP/1.1 500 Internal cRemoteSocket error\n";
        requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(errorCode), 0, errorCode.Length);
      }

      // 2. Sending cRemoteSocket response headers
      if (webEx.Response?.Headers?.Count > 0)
      {
        foreach (var tmpKey in webEx.Response.Headers.AllKeys)
        {
          var httpResponseString = $"{tmpKey}: {webEx.Response.Headers[tmpKey]}\n";
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
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Error, "IncomingClientRequest.ProcessWebException(EXCEPTION2) : {0} -> {1} \n{2}", requestObj.ClientRequestObj.GetRequestedUrl(), ex.Message, ex.StackTrace);
      }
    }


    /// <summary>
    /// Send HTTP Redirect location to the client system.
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="redirectLocation"></param>
    public void SendRedirect2Client(RequestObj requestObj, string redirectLocation)
    {
      var newLine = requestObj.ClientRequestObj.RequestLine.NewlineString;
      var dateTimeNow = String.Format("{0:r}", DateTime.Now);
      var data = $"<html>{newLine}" +
                 $"<head>{newLine}" +
                 $"<title> 302 Found </title>{newLine}" +
                 $"</head><body>{newLine}" +
                 $"<h1> Found</ h1 >{newLine}" +
                 $"<p> The document has moved <a href=\"{redirectLocation}\"> here </ a >.</ p >{newLine}" +
                 $"</body></html>{newLine}";
      var redirectCode = $"HTTP/307 Temporary Redirect{newLine}" + 
                         $"Server: nginx{newLine}" +
                         $"Connection: close{newLine}" +
                         $"Content-Type: text/html{newLine}" +
                         $"Content-Length: {data.Length}{newLine}" +
                         $"Date: {dateTimeNow}{newLine}{newLine}";
      requestObj.ClientRequestObj.ClientBinaryWriter.Write(Encoding.ASCII.GetBytes(redirectCode), 0, redirectCode.Length);

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
