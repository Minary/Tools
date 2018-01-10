namespace HttpReverseProxy
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


  public class RequestHandlerHttp
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


    #region PUBLIC

    /// <summary>
    /// Initializes a new instance of the <see cref="RequestHandlerHttp"/> class.
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    public RequestHandlerHttp(RequestObj requestObj)
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
      PluginInstruction pluginInstr;
      this.requestObj.ClientRequestObj.ClientWebRequestHandler = new IncomingClientRequest();

      while (true)
      {
        // (Re) Initialize request object values like client request and server response headers
        pluginInstr = null;
        //this.requestObj.InitRequestValues();
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(): New {0} request to {1}{2}", this.requestObj.ProxyProtocol.ToString(), this.requestObj.ClientRequestObj.Host, this.requestObj.ClientRequestObj.RequestLine.Path);

        try
        {
          // Receive client data
          this.ReadClientRequestHeaders();

          // Call post tcp-client request methodString of each loaded plugin
          bool mustBreakLoop = this.PostClientHeadersRequest();
          if (mustBreakLoop == true)
          {
            break;
          }

          // Re(re)quest server
          pluginInstr = this.SendClientRequestToServer();

          // Send server response to client
          this.SendServerResponseToClient(pluginInstr);
        }
        catch (ClientNotificationException cnex)
        {
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          var innerException = cnex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warning, "HttpReverseProxy.ProcessClientRequest(ClientNotificationException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, cnex.Message, cnex.StackTrace);
          break;
        }
        catch (ProxyErrorException peex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          var innerException = peex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpReverseProxy.ProcessClientRequest(ProxyErrorException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, peex.Message, peex.StackTrace);
          break;
        }
        catch (WebException wex)
        {
          var innerException = wex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warning, "HttpReverseProxy.ProcessClientRequest(WebException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, wex.Message, wex.StackTrace);
          this.clientErrorHandler.ProcessWebException(this.requestObj, wex);
        }
        catch (System.IO.IOException ioex)
        {
          var innerException = ioex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(IOException): Client system closed the connection");
          break;
        }
        catch (ObjectDisposedException odex)
        {
          var innerException = odex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(ObjectDisposedException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, odex.Message, odex.StackTrace);
          break;
        }
        catch (SocketException sex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          var innerException = sex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warning, "HttpReverseProxy.ProcessClientRequest(SocketException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, sex.Message, sex.StackTrace);
          break;
        }
        catch (Exception ex)
        {
          var innerException = ex.InnerException?.Message ?? "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "HttpReverseProxy.ProcessClientRequest(Exception): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, ex.Message, ex.StackTrace);
          break;
        }

        // If remote socket was closed or the client sent a "Conection: close" headerByteArray
        // break out of the loop
        if (this.CloseClientServerConnection())
        {
          break;

        // Set keep-alive value
        }
        else
        {
          this.requestObj.ClientRequestObj.ClientBinaryReader.BaseStream.ReadTimeout = 3000;
        }

        // Reinitialize request object.
        this.requestObj.InitRequestValues();
      }
    }

    #endregion


    #region PRIVATE

    private bool PostClientHeadersRequest()
    {
      bool mustBreakLoop = false;
      PluginInstruction pluginInstr;

      try
      {
        pluginInstr = Lib.PluginCalls.PostClientHeadersRequest(this.requestObj);

        if (pluginInstr.Instruction == Instruction.RedirectToNewUrl)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(): PostClientHeaders Rrequest instruction: {0} -> {1}", pluginInstr.Instruction, pluginInstr.InstructionParameters.Data);
          this.clientInstructionHandler.Redirect(this.requestObj, pluginInstr.InstructionParameters);
          mustBreakLoop = true;
        }
        else if (pluginInstr.Instruction == Instruction.SendBackLocalFile)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(): PostClientHeaders Rrequest instruction: {0} -> {1}", pluginInstr.Instruction, pluginInstr.InstructionParameters.Data);
          this.clientInstructionHandler.SendLocalFileToClient(this.requestObj, pluginInstr.InstructionParameters);
          mustBreakLoop = true;
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ProcessClientRequest(): PostClientHeadersRequest(EXCEPTION): {0} ", ex.Message);
      }

      return mustBreakLoop;
    }


    private void ReadClientRequestHeaders()
    {
      // Read Client request line
      this.requestObj.ClientRequestObj.ClientWebRequestHandler.ReceiveClientRequestLine(this.requestObj);

      // Read Client request and pass request, headers and data to plugins
      this.requestObj.ClientRequestObj.ClientWebRequestHandler.ReceiveClientRequestHeaders(this.requestObj);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.ReadClientRequestHeaders(): {0} requesting {1}", this.requestObj.SrcIp, this.requestObj.ClientRequestObj.GetRequestedUrl());
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ReadClientRequestHeaders(): Data transmission mode C2S is: {0}", this.requestObj.ProxyDataTransmissionModeC2S.ToString());

      // Interrupt request if target system is within the private IP address ranges
      if (Lib.Common.IsIpPartOfPrivateNetwork(this.requestObj.ClientRequestObj.Host))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Warning, "HttpReverseProxy.ReadClientRequestHeaders(): Requested host {0} is part of private network", this.requestObj.SrcIp, this.requestObj.ClientRequestObj.Host);
        throw new ClientNotificationException("The requested host is invalid");
      }
    }


    private PluginInstruction SendClientRequestToServer()
    {
      PluginInstruction pluginInstruction = null;
      while (pluginInstruction == null || pluginInstruction.Instruction == Instruction.ReloadUrlWithHttps)
      {
        Logging.Instance.LogMessage(
                                    this.requestObj.Id,
                                    this.requestObj.ProxyProtocol,
                                     Loglevel.Debug,
                                    "HttpReverseProxy.SendRequestToServer(): {0}",
                                    (pluginInstruction == null) ? "Forward clinet request to server" : "Plugin instruction:Instruction.ReloadUrlWithHttps");

        // 4. Forward client request data to the server
        this.ForwardClientRequestToServer();

        // 5. Call post remoteSocket response methodString of each loaded plugin
        pluginInstruction = Lib.PluginCalls.PostServerHeadersResponse(this.requestObj);

        // 6. Determine data transmission mode S2C
        this.DetermineDataTransmissionModeS2C();
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendRequestToServer(): Data transmission mode S2C is: {0}", this.requestObj.ProxyDataTransmissionModeS2C);
      }

      return pluginInstruction;
    }


    private void SendServerResponseToClient(PluginInstruction pluginInstruction)
    {
      // Send server response to client: Redirect
      if (pluginInstruction.Instruction == Instruction.RedirectToNewUrl)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendServerResponseToClient(): Plugin instruction:Instruction.RedirectToNewUrl");


      // Send server response to client: Regular server response
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendServerResponseToClient(): Plugin instruction:Instruction.DoNothing");

        // Determine whether response content type must be processed
        bool mustBeProcessed = this.IsServerResponseDataProcessable();
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendServerResponseToClient(): SERVER RESPONSE : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));

        // If the server response contains the "Content-Length: ..." header
        // replace it by the "Transfer-Encoding: chunked" header
        if (this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Content-Length"))
        {
          this.requestObj.ServerResponseObj.ResponseHeaders.Remove("Content-Length");

          if (!this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Transfer-Encoding"))
          {
            this.requestObj.ServerResponseObj.ResponseHeaders.Add("Transfer-Encoding", new List<string>() { "Chunked" });
          }
        }

        this.requestObj.ServerRequestHandler.ForwardStatusLineS2C(this.requestObj.ServerResponseObj.StatusLine);
        this.requestObj.ServerRequestHandler.ForwardHeadersS2C(this.requestObj.ServerResponseObj.ResponseHeaders, this.requestObj.ServerResponseObj.StatusLine.NewlineBytes);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendServerResponseToClient(): Headers and terminating empty line ({0}) sent", this.requestObj.ServerResponseObj.StatusLine.NewlineType);
        this.requestObj.ServerResponseObj.NoTransferredBytes = this.requestObj.ServerRequestHandler.RelayDataS2C(mustBeProcessed);
        string redirectLocation = this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location") ? "/" + this.requestObj.ServerResponseObj.ResponseHeaders["Location"][0] : string.Empty;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.SendServerResponseToClient(): {0}{1}, {2}, {3} bytes", this.requestObj.ServerResponseObj.StatusLine.StatusCode, redirectLocation, this.requestObj.ProxyDataTransmissionModeS2C, this.requestObj.ServerResponseObj.NoTransferredBytes);

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.SendServerResponseToClient(): DONE! All data transferred to client");
      }
    }


    private void DetermineDataTransmissionModeS2C()
    {
      // Transfer behavior is "Content-Length"
      if (this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Content-Length"))
      {
        string contentLen = this.requestObj.ServerResponseObj.ResponseHeaders["Content-Length"][0];
        this.requestObj.ServerResponseObj.ContentLength = int.Parse(contentLen);

        if (this.requestObj.ServerResponseObj.ContentLength > 0)
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.FixedContentLength;
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


    private bool CloseClientServerConnection()
    {
      if (this.requestObj.ServerRequestHandler.ServerSocket.Connected == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.CloseClientServerConnection(): Server closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.TcpClientConnection.Connected == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.CloseClientServerConnection(): Client closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.ClientRequestObj.IsClientKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.CloseClientServerConnection(): Client HTTP connection \"close\". Closing connection");
        return true;
      }
      else if (this.requestObj.IsServerKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.CloseClientServerConnection(): Server HTTP connection \"close\". Closing connection");
        return true;
      }

      return false;
    }


    private void ForwardClientRequestToServer()
    {
      // 1. Close old server request streams
      if (this.requestObj.ServerRequestHandler != null)
      {
        this.requestObj.ServerRequestHandler.CloseServerConnection();
      }

      // 1.1 Reset previously received server response details
      this.requestObj.ServerResponseObj.ResponseHeaders.Clear();
      this.requestObj.ServerResponseObj.StatusLine.Reset();

      // If remote server requires HTTPS create an SSL based socket stream.
      // Reasons : Plugin.SslStripn: Http redirect cache record
      //           Plugin.SslStripn: Hsts cache record
      //           Plugin.SslStripn: SslStrip cache record
      if (this.requestObj.ProxyProtocol == ProxyProtocol.Https)
      {
        this.requestObj.ServerRequestHandler = new ToServer.TcpClientSsl(this.requestObj, this.requestObj.ClientRequestObj.ClientBinaryReader, this.requestObj.ClientRequestObj.ClientBinaryWriter);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ForwardClientRequestToServer(): Create HTTPS socket connection to {0}", this.requestObj.ClientRequestObj.Host);
      }
      else
      {
        this.requestObj.ServerRequestHandler = new ToServer.TcpClientPlainText(this.requestObj, this.requestObj.ClientRequestObj.ClientBinaryReader, this.requestObj.ClientRequestObj.ClientBinaryWriter);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ForwardClientRequestToServer(): Create HTTP socket connection to {0}", this.requestObj.ClientRequestObj.Host);
      }

      // 2. Send tcp-client request headers to remoteSocket
      this.requestObj.ServerRequestHandler.OpenServerConnection(this.requestObj.ClientRequestObj.Host);
      this.requestObj.ServerRequestHandler.ForwardRequestC2S(this.requestObj.ClientRequestObj.RequestLine.MethodString, this.requestObj.ClientRequestObj.RequestLine.Path, this.requestObj.ClientRequestObj.RequestLine.HttpVersion, this.requestObj.ClientRequestObj.RequestLine.NewlineBytes);
      this.requestObj.ServerRequestHandler.ForwardHeadersC2S(this.requestObj.ClientRequestObj.ClientRequestHeaders, this.requestObj.ClientRequestObj.RequestLine.NewlineBytes);

      // 3. Send tcp-client request data to remoteSocket
      bool mustBeProcessed = this.IsClientRequestDataProcessable();
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.ForwardClientRequestToServer(): CLIENT REQUEST : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));
      SniffedDataChunk sniffedDataChunk = new SniffedDataChunk(Config.MaxSniffedClientDataSize);

      this.requestObj.ServerRequestHandler.RelayDataC2S(mustBeProcessed, sniffedDataChunk);
      this.EditClientRequestData(sniffedDataChunk);

      // 4 Read remotesocket response headers
      this.requestObj.ServerRequestHandler.ReadServerStatusLine(this.requestObj);
      this.requestObj.ServerRequestHandler.ReadServerResponseHeaders(this.requestObj.ServerResponseObj);
    }


    private bool IsServerResponseDataProcessable()
    {
      // 1. Server response "Content-Type" is labelled as "supported"
      if (!this.supportedContentTypes.ContainsKey(this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.IsServerResponseDataProcessable():\"{0}\" is not processed", this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Server response "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ServerResponseObj.ContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.IsServerResponseDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseObj.ContentLength, dataDownloadUpperLimit);
        return false;
      }

      return true;
    }


    private bool IsClientRequestDataProcessable()
    {
      // 1. Client request "Content-Type" is labelled as "supported"
      if (!this.supportedContentTypes.ContainsKey(this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.IsClientRequestDataProcessable(): \"{ 0}\" is not processed", this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Client request "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ClientRequestObj.ContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.IsClientRequestDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseObj.ContentLength, dataDownloadUpperLimit);
        return false;
      }

      return true;
    }


    private void EditClientRequestData(SniffedDataChunk sniffedDataChunk)
    {
      // Append client request headers to the log data string
      try
      {
        foreach (string key in this.requestObj.ClientRequestObj.ClientRequestHeaders.Keys)
        {
          string logData = string.Join("..", this.requestObj.ClientRequestObj.ClientRequestHeaders[key]);
          this.requestObj.HttpLogData += $"..{key}: {logData}";
        }
      }
      catch (Exception)
      {
      }

      // Append client request data to the log data string
      if (sniffedDataChunk?.TotalBytesWritten > 0)
      {
        this.requestObj.HttpLogData += "...." + sniffedDataChunk.GetDataString();
      }
    }

    #endregion

  }
}