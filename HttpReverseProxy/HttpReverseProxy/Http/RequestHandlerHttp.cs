﻿namespace HttpReverseProxy.Http
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
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
        this.requestObj.InitRequestValues();

        try
        {
          // 1. Read Client request and pass request, headers and data to plugins
          this.requestObj.ClientRequestObj.ClientWebRequestHandler.ReceiveClientRequestHeaders(this.requestObj);
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): Data transmission mode C2S is: {0}", this.requestObj.ProxyDataTransmissionModeC2S.ToString());

          // 2. Call post tcp-client request methodString of each loaded plugin
          try
          {
            pluginInstr = Lib.PluginCalls.PostClientHeadersRequest(this.requestObj);

            if (pluginInstr.Instruction == Instruction.RedirectToNewUrl)
            {
              Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): PostClientHeaders Rrequest instruction: {0} -> {1}", pluginInstr.Instruction, pluginInstr.InstructionParameters.Data);
              this.clientInstructionHandler.Redirect(this.requestObj, pluginInstr.InstructionParameters.Data);
              break;
            }
            else if (pluginInstr.Instruction == Instruction.SendBackLocalFile)
            {
              Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): PostClientHeaders Rrequest instruction: {0} -> {1}", pluginInstr.Instruction, pluginInstr.InstructionParameters.Data);
              this.clientInstructionHandler.SendLocalFileToClient(this.requestObj, pluginInstr.InstructionParameters.Data);
              break;
            }
          }
          catch (Exception ex)
          {
            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): PostClientHeadersRequest(EXCEPTION): {0} ", ex.Message);
          }

          // 3. Re(re)quest server
          pluginInstr = null;
          while (pluginInstr == null || pluginInstr.Instruction == Instruction.ReloadUrlWithHttps)
          {
            Logging.Instance.LogMessage(
                                        this.requestObj.Id,
                                        Logging.Level.DEBUG,
                                        "HttpReverseProxy.ProcessClientRequest(): {0}",
                                        (pluginInstr == null) ? "Forward clinet request to server" : "Plugin instruction:Instruction.ReloadUrlWithHttps");

            // 4. Forward client request data to the server
            this.ForwardClientRequestToServer();

            // 5. Call post remoteSocket response methodString of each loaded plugin
            pluginInstr = Lib.PluginCalls.PostServerHeadersResponse(this.requestObj);

            // 6. Determine data transmission mode S2C
            this.DetermineDataTransmissionModeS2C(this.requestObj);
            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): Data transmission mode S2C is: {0}", this.requestObj.ProxyDataTransmissionModeS2C);
          }

          if (pluginInstr.Instruction == Instruction.RedirectToNewUrl)
          {
            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): Plugin instruction:Instruction.RedirectToNewUrl");
          }
          else
          {
            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): Plugin instruction:Instruction.DoNothing");

            // 5.6 Determine whether response content type must be processed
            bool mustBeProcessed = this.IsServerResponseDataProcessable(this.requestObj);
            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): SERVER RESPONSE : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));

            this.requestObj.ServerRequestHandler.ForwardStatusLineS2C(this.requestObj.ServerStatusResponseObj);
            this.requestObj.ServerRequestHandler.ForwardHeadersS2C(this.requestObj.ServerResponseMetaDataObj.ResponseHeaders);
            this.requestObj.ServerRequestHandler.RelayDataS2C(mustBeProcessed);

            Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): DONE! All data transferred to client");
          }
        }
        catch (ClientNotificationException cnex)
        {
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (cnex.InnerException != null) ? cnex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.WARNING, "HttpReverseProxy.ProcessClientRequest(ClientNotificationException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, cnex.Message, cnex.StackTrace);
          break;
        }
        catch (ProxyErrorException peex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (peex.InnerException != null) ? peex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.ERROR, "HttpReverseProxy.ProcessClientRequest(ProxyErrorException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, peex.Message, peex.StackTrace);
          break;
        }
        catch (WebException wex)
        {
          string innerException = (wex.InnerException != null) ? wex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.WARNING, "HttpReverseProxy.ProcessClientRequest(WebException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, wex.Message, wex.StackTrace);
          this.clientErrorHandler.ProcessWebException(this.requestObj, wex);
        }
        catch (System.IO.IOException ioex)
        {
// ClientNotificationException cnex = new ClientNotificationException();
//// cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.InternalServerError);
//// this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (ioex.InnerException != null) ? ioex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.ERROR, "HTTPReverseProxy.ProcessClientRequest(IOException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, ioex.Message, ioex.StackTrace);
//          break;
        }
        catch (ObjectDisposedException odex)
        {
          string innerException = (odex.InnerException != null) ? odex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.ERROR, "HTTPReverseProxy.ProcessClientRequest(ObjectDisposedException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, odex.Message, odex.StackTrace);
          break;
        }
        catch (SocketException sex)
        {
          ClientNotificationException cnex = new ClientNotificationException();
          cnex.Data.Add(StatusCodeLabel.StatusCode, HttpStatusCode.BadRequest);
          this.clientErrorHandler.SendErrorMessage2Client(this.requestObj, cnex);

          string innerException = (sex.InnerException != null) ? sex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.WARNING, "HTTPReverseProxy.ProcessClientRequest(SocketException): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, sex.Message, sex.StackTrace);
          break;
        }
        catch (Exception ex)
        {
          string innerException = (ex.InnerException != null) ? ex.InnerException.Message : "No inner exception found";
          Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.ERROR, "HTTPReverseProxy.ProcessClientRequest(Exception): Inner exception:{0}\r\nRegular exception: {1}\r\n{2}", innerException, ex.Message, ex.StackTrace);
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
      if (this.requestObj.ServerResponseMetaDataObj.ResponseHeaders.ContainsKey("Content-Length"))
      {
        string contentLen = this.requestObj.ServerResponseMetaDataObj.ResponseHeaders["Content-Length"].ToString();
        this.requestObj.ServerResponseMetaDataObj.ContentLength = int.Parse(contentLen);

        if (this.requestObj.ServerResponseMetaDataObj.ContentLength > 0)
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.ContentLength;
        }
        else if (this.requestObj.ServerResponseMetaDataObj.ContentLength == 0)
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.NoDataToTransfer;
        }
        else
        {
          this.requestObj.ProxyDataTransmissionModeS2C = DataTransmissionMode.Error;
        }

        // Transfer behavior is "Chunked"
      }
      else if (this.requestObj.ServerResponseMetaDataObj.ResponseHeaders.ContainsKey("Transfer-Encoding"))
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
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HTTPReverseProxy.CloseClientServerConnection(): Server closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.TcpClientConnection.Connected == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HTTPReverseProxy.CloseClientServerConnection(): Client closed connection. Closing connection");
        return true;
      }
      else if (this.requestObj.ClientRequestObj.IsClientKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HTTPReverseProxy.CloseClientServerConnection(): Client HTTP connection \"close\". Closing connection");
        return true;
      }
      else if (this.requestObj.IsServerKeepAlive == false)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HTTPReverseProxy.CloseClientServerConnection(): Server HTTP connection \"close\". Closing connection");
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
      this.requestObj.ServerResponseMetaDataObj.ResponseHeaders.Clear();
      this.requestObj.ServerStatusResponseObj.Reset();

      // If remote server requires HTTPS create an SSL based socket stream.
      // Reasons : Plugin.SslStripn: Http redirect cache record
      //           Plugin.SslStripn: Hsts cache record
      //           Plugin.SslStripn: SslStrip cache record
      if (this.requestObj.ClientRequestObj.Scheme == "https")
      {
        this.requestObj.ServerRequestHandler = new ToServer.TcpClientSsl(this.requestObj, this.requestObj.ClientRequestObj.ClientBinaryReader, this.requestObj.ClientRequestObj.ClientBinaryWriter);
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ForwardClientRequestToServer(): Create HTTPS socket connection to {0}", this.requestObj.ClientRequestObj.Host);
      }
      else
      {
        this.requestObj.ServerRequestHandler = new ToServer.TcpClientPlainText(this.requestObj, this.requestObj.ClientRequestObj.ClientBinaryReader, this.requestObj.ClientRequestObj.ClientBinaryWriter);
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ForwardClientRequestToServer(): Create HTTP socket connection to {0}", this.requestObj.ClientRequestObj.Host);
      }

      // 4. Send tcp-client request headers to remoteSocket
      this.requestObj.ServerRequestHandler.OpenServerConnection(this.requestObj.ClientRequestObj.Host);
      this.requestObj.ServerRequestHandler.ForwardRequestC2S(this.requestObj.ClientRequestObj.MethodString, this.requestObj.ClientRequestObj.Path, this.requestObj.ClientRequestObj.HttpVersion);
      this.requestObj.ServerRequestHandler.ForwardHeadersC2S(this.requestObj.ClientRequestObj.ClientRequestHeaders);

      // 5. Send tcp-client request data to remoteSocket
      bool mustBeProcessed = this.IsClientRequestDataProcessable(this.requestObj);
      Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.DEBUG, "HttpReverseProxy.ProcessClientRequest(): CLIENT REQUEST : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));
      SniffedDataChunk sniffedDataChunk = new SniffedDataChunk(Config.MaxSniffedClientDataSize);
      this.requestObj.ServerRequestHandler.RelayDataC2S(mustBeProcessed, sniffedDataChunk);
      this.EditClientRequestData(this.requestObj, sniffedDataChunk);

      // 6 Read remotesocket response headers
      this.requestObj.ServerRequestHandler.ReadServerStatusLine(this.requestObj.ServerStatusResponseObj);
      this.requestObj.ServerRequestHandler.ReadServerResponseHeaders(this.requestObj.ServerResponseMetaDataObj);
    }


    private bool IsServerResponseDataProcessable(RequestObj requestObj)
    {
      // 1. Server response "Content-Type" is labelled as "supported"
      if (!this.SupportedContentTypes.ContainsKey(this.requestObj.ServerResponseMetaDataObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.INFO, "HTTPReverseProxy.IsServerResponseDataProcessable():\"{0}\" is not processed", this.requestObj.ServerResponseMetaDataObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Server response "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ServerResponseMetaDataObj.ContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.INFO, "HTTPReverseProxy.IsServerResponseDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseMetaDataObj.ContentLength, dataDownloadUpperLimit);
        return false;
      }

      return true;
    }


    private bool IsClientRequestDataProcessable(RequestObj requestObj)
    {
      // 1. Client request "Content-Type" is labelled as "supported"
      if (!this.SupportedContentTypes.ContainsKey(this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType))
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.INFO, "HTTPReverseProxy.IsClientRequestDataProcessable(): \"{ 0}\" is not processed", this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentType);
        return false;
      }

      // 2. Client request "Content-Length" is > UPPER_LIMIT
      if (this.requestObj.ClientRequestObj.ClientRequestContentLength > this.dataDownloadUpperLimit)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, Logging.Level.INFO, "HTTPReverseProxy.IsClientRequestDataProcessable(): The content length is greater than the upper limit (contentLength:{0}, UpperLimit:{1}", this.requestObj.ServerResponseMetaDataObj.ContentLength, dataDownloadUpperLimit);
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
          this.requestObj.HttpLogData += string.Format("..{0}: {1}", key, requestObj.ClientRequestObj.ClientRequestHeaders[key]);
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