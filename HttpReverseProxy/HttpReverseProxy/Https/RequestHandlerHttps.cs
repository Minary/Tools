namespace HttpReverseProxy.Https
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
  using System.Net;
  using System.Net.Sockets;


  public class RequestHandlerHttps
  {

    #region MEMBERS

    private RequestObj requestObj;
    private ClientErrorHandler clientErrorHandler;
    private ToClient.InstructionHandler clientInstructionHandler;
    private int dataDownloadUpperLimit = 5 * 1000 * 1000; // Limit 5 mb
    // private int dataUploadUpperLimit = 5 * 1000 * 1000;   // Limit 5 mb
    private Dictionary<string, bool> supportedContentTypes = new Dictionary<string, bool>()
    {
      { "application/x-www-form-urlencoded", true },
      { "multipart/form-data", true },
      { "text/html", true },
      { "text/xml", true }
    };

    #endregion


    #region PROPERTIES

    public int DataDownloadUpperLimit { get { return this.dataDownloadUpperLimit; } set { } }

    public Dictionary<string, bool> SupportedContentTypes { get { return this.supportedContentTypes; } set { } }

    public RequestObj RequestObj { get { return this.requestObj; } set { this.requestObj = value; } }

    #endregion


    #region PUBLIC

    /// <summary>
    /// Initializes a new instance of the <see cref="RequestHandlerHttp"/> class.
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    public RequestHandlerHttps(RequestObj requestObj)
    {
      this.requestObj = requestObj;
      this.clientErrorHandler = new ClientErrorHandler();
      this.clientInstructionHandler = new ToClient.InstructionHandler();
    }


    /// <summary>
    ///
    /// </summary>
    public void ProcessClientRequest()
    {
      this.requestObj.ClientRequestObj.ClientWebRequestHandler = new IncomingClientRequest();

      while (true)
      {
        // (Re) Initialize request object values like client request and server response headers
        this.requestObj.InitRequestValues();
        
        try
        {
          // 0. Read Client request line
          this.requestObj.ClientRequestObj.ClientWebRequestHandler.ReceiveClientRequestLine(this.requestObj);

          // 1. Read Client request headers
          this.requestObj.ClientRequestObj.ClientWebRequestHandler.ReceiveClientRequestHeaders(this.requestObj);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.ProcessClientRequest(): {0} requestint {1}", this.requestObj.SrcIp, this.requestObj.ClientRequestObj.GetRequestedUrl());
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.ProcessClientRequest(): Data transmission mode C2S is: {0}", this.requestObj.ProxyDataTransmissionModeC2S.ToString());

          // 1.1 Interrupt request if target system is within the private IP address ranges
          if (Network.Instance.IpPartOfPrivateNetwork(this.requestObj.ClientRequestObj.Host))
          {
            Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warnung, "HttpReverseProxy.ProcessClientRequest(): Requested host {0} is part of private network", this.requestObj.SrcIp, this.requestObj.ClientRequestObj.Host);
            throw new ClientNotificationException("The requested host is invalid");
          }

          // 2. Forward client request data to the server
          this.ForwardClientRequestToServer();

          // 3. Determine data transmission mode S2C
          this.DetermineDataTransmissionModeS2C(this.requestObj);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.ProcessClientRequest(): Data transmission mode S2C is: {0}", this.requestObj.ProxyDataTransmissionModeS2C);

          bool mustBeProcessed = false;
          this.requestObj.ServerRequestHandler.ForwardStatusLineS2C(this.requestObj.ServerResponseObj.StatusLine);
          this.requestObj.ServerRequestHandler.ForwardHeadersS2C(this.requestObj.ServerResponseObj.ResponseHeaders, this.requestObj.ServerResponseObj.StatusLine.NewlineBytes);
          this.requestObj.ServerResponseObj.NoTransferredBytes = this.requestObj.ServerRequestHandler.RelayDataS2C(mustBeProcessed);

          string redirectLocation = this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location") ? "/" + this.requestObj.ServerResponseObj.ResponseHeaders["Location"][0] : string.Empty;
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.ProcessClientRequest(): {0}{1}, {2}, {3} bytes", this.requestObj.ServerResponseObj.StatusLine.StatusCode, redirectLocation, this.requestObj.ProxyDataTransmissionModeS2C, this.requestObj.ServerResponseObj.NoTransferredBytes);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.ProcessClientRequest(): DONE! All data transferred to client");
        }
        catch (ClientNotificationException cnex)
        {
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (cnex.InnerException != null) ? cnex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warnung, "HttpsReverseProxy.ProcessClientRequest(ClientNotificationException): Inner exception:{0}", innerException);
          break;
        }
        catch (ProxyErrorException peex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (peex.InnerException != null) ? peex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpsReverseProxy.ProcessClientRequest(ProxyErrorException): Inner exception:{0}", innerException);
          break;
        }
        catch (WebException wex)
        {
          string innerException = (wex.InnerException != null) ? wex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warnung, "HttpsReverseProxy.ProcessClientRequest(WebException): Inner exception:{0}", innerException);
          this.clientErrorHandler.ProcessWebException(this.requestObj, wex);
        }
        catch (System.IO.IOException ioex)
        {
          string innerException = (ioex.InnerException != null) ? string.Format("INNER EXCEPTION: {0}={1}", ioex.InnerException.GetType(), ioex.InnerException.Message) : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpsReverseProxy.ProcessClientRequest(IOException): Inner exception:{0}, Regular exception: {1}={2}", innerException, ioex.GetType(), ioex.Message);
          break;
        }
        catch (ObjectDisposedException odex)
        {
          string innerException = (odex.InnerException != null) ? odex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpsReverseProxy.ProcessClientRequest(ObjectDisposedException): Inner exception:{0}, Regular exception: {1}", innerException, odex.Message);
          break;
        }
        catch (SocketException sex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (sex.InnerException != null) ? sex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warnung, "HttpsReverseProxy.ProcessClientRequest(SocketException): Inner exception:{0}, Regular exception: {1}", innerException, sex.Message);
          break;
        }
        catch (Exception ex)
        {
          string innerException = (ex.InnerException != null) ? ex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpsReverseProxy.ProcessClientRequest(Exception): Inner exception:{0}, Regular exception: {1}", innerException, ex.Message);
          break;
        }

        // If remote socket was closed or the client sent a "Conection: close" headerByteArray
        // break out of the loop
        if (this.CloseClientServerConnection(this.requestObj))
        {
          break;
        }
      }
    }

    #endregion


    #region PRIVATE

    private void DetermineDataTransmissionModeS2C(RequestObj requestObj)
    {
      // Transfer behavior is "Content-Length"
      if (this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Content-Length"))
      {
        string contentLen = this.requestObj.ServerResponseObj.ResponseHeaders["Content-Length"][0];
        this.requestObj.ServerResponseObj.ContentLength = int.Parse(contentLen);

        if (this.requestObj.ServerResponseObj.ContentLength > 0)
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.ContentLength;
        }
        else if (this.requestObj.ServerResponseObj.ContentLength == 0)
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.NoDataToTransfer;
        }
        else
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.Error;
        }

      // Transfer behavior is "Chunked"
      }
      else if (this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Transfer-Encoding"))
      {
        this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.Chunked;

      // Transfer behavior is "Relay blindly"
      }
      else
      {
        this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.RelayBlindly;
      }
    }


    private bool CloseClientServerConnection(RequestObj requestObj)
    {
      if (this.requestObj.ServerRequestHandler.ServerSocket.Connected == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.CloseClientServerConnection(): Server closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.TcpClientConnection.Connected == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.CloseClientServerConnection(): Client closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.ClientRequestObj.IsClientKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.CloseClientServerConnection(): Client HTTP connection \"close\". Closing connection");
        return true;
      }
      else if (this.requestObj.IsServerKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.CloseClientServerConnection(): Server HTTP connection \"close\". Closing connection");
        return true;
      }

      return false;
    }


    private void ForwardClientRequestToServer()
    {
      // 3. Close old server request streams
      if (this.RequestObj.ServerRequestHandler != null)
      {
        this.requestObj.ServerRequestHandler.CloseServerConnection();
      }

      // 3.1 Reset previously received server response details
      this.requestObj.ServerResponseObj.ResponseHeaders.Clear();
      this.requestObj.ServerResponseObj.StatusLine.Reset();

      // If remote server requires HTTPS create an SSL based socket stream.
      // Reasons : Plugin.SslStripn: Http redirect cache record
      //           Plugin.SslStripn: Hsts cache record
      //           Plugin.SslStripn: SslStrip cache record
      this.requestObj.ServerRequestHandler = new ToServer.TcpClientSsl(this.requestObj, this.requestObj.ClientRequestObj.ClientBinaryReader, this.requestObj.ClientRequestObj.ClientBinaryWriter);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpsReverseProxy.ForwardClientRequestToServer(): Create HTTPS socket connection to {0}", this.requestObj.ClientRequestObj.Host);

      // 4. Send tcp-client request headers to remoteSocket
      this.requestObj.ServerRequestHandler.OpenServerConnection(this.requestObj.ClientRequestObj.Host);
      this.requestObj.ServerRequestHandler.ForwardRequestC2S(this.requestObj.ClientRequestObj.RequestLine.MethodString, this.requestObj.ClientRequestObj.RequestLine.Path, this.requestObj.ClientRequestObj.RequestLine.HttpVersion, this.requestObj.ClientRequestObj.RequestLine.NewlineBytes);
      this.requestObj.ServerRequestHandler.ForwardHeadersC2S(this.requestObj.ClientRequestObj.ClientRequestHeaders, this.requestObj.ClientRequestObj.RequestLine.NewlineBytes);

      // 5. Send tcp-client request data to remoteSocket
      SniffedDataChunk sniffedDataChunk = new SniffedDataChunk(Config.MaxSniffedClientDataSize);
      this.requestObj.ServerRequestHandler.RelayDataC2S(false, sniffedDataChunk);
      this.EditClientRequestData(this.requestObj, sniffedDataChunk);

      // 6 Read remotesocket response headers
      this.requestObj.ServerRequestHandler.ReadServerStatusLine(this.requestObj);
      this.requestObj.ServerRequestHandler.ReadServerResponseHeaders(this.requestObj.ServerResponseObj);
    }


    private bool IsServerResponseDataProcessable(RequestObj requestObj)
    {
      // 1. Server response "Content-Type" is labelled as "supported"
      if (!this.SupportedContentTypes.ContainsKey(this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.IsServerResponseDataProcessable():\"{0}\" is not processed", this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Server response "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ServerResponseObj.ContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.IsServerResponseDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseObj.ContentLength, dataDownloadUpperLimit);
        return false;
      }

      return true;
    }


    private bool IsClientRequestDataProcessable(RequestObj requestObj)
    {
      // 1. Client request "Content-Type" is labelled as "supported"
      if (!this.SupportedContentTypes.ContainsKey(this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.IsClientRequestDataProcessable(): \"{ 0}\" is not processed", this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Client request "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ClientRequestObj.ClientRequestContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpsReverseProxy.IsClientRequestDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseObj.ContentLength, dataDownloadUpperLimit);
        return false;
      }

      return true;
    }


    private void EditClientRequestData(RequestObj requestObj, SniffedDataChunk sniffedDataChunk)
    {
      // Append client request headers to the log data string
      try
      {
        foreach (string key in requestObj.ClientRequestObj.ClientRequestHeaders.Keys)
        {
          string logData = string.Join("..", requestObj.ClientRequestObj.ClientRequestHeaders[key]);
          this.requestObj.HttpLogData += string.Format("..{0}: {1}", key, logData);
        }
      }
      catch (Exception)
      {
      }

      // Append client request data to the log data string
      if (sniffedDataChunk != null && sniffedDataChunk.TotalBytesWritten > 0)
      {
        this.requestObj.HttpLogData += "...." + sniffedDataChunk.GetDataString();
      }
    }

    #endregion

  }
}