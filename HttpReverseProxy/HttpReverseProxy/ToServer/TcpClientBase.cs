namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Class.Server;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Net.Sockets;
  using System.Text;
  using System.Text.RegularExpressions;


  public class TcpClientBase : TcpClientRaw, IOutgoingRequestClient
  {

    #region MEMBERS

    protected RequestObj requestObj;

    protected MyBinaryReader webServerStreamReader;
    protected BinaryWriter webServerStreamWriter;

    protected MyBinaryReader clientStreamReader;
    protected BinaryWriter clientStreamWriter;

    protected TcpClient httpWebServerSocket;
    protected int remoteTcpPort;

    private const int MaxBufferSize = 4096;

    #endregion


    #region INTERFACE : IOutgoingRequestClient

    public TcpClient ServerSocket { get { return this.httpWebServerSocket; } set { } }

    #region Server connection

    virtual public void OpenServerConnection(string host)
    {
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.OpenServerConnection()");

      if (string.IsNullOrEmpty(host))
      {
        throw new Exception("Host is invalid");
      }

      this.httpWebServerSocket = new TcpClient();
      this.httpWebServerSocket.NoDelay = true;
      this.httpWebServerSocket.Connect(host, this.remoteTcpPort);

      this.webServerStreamReader = new MyBinaryReader(this.requestObj.ProxyProtocol, this.httpWebServerSocket.GetStream(), 8192, Encoding.UTF8, this.requestObj.Id);
      this.webServerStreamWriter = new BinaryWriter(this.httpWebServerSocket.GetStream());
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="pNetworkStream"></param>
    public virtual void CloseServerConnection()
    {
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.CloseServerConnection()");

      if (this.webServerStreamReader != null)
      {
        this.webServerStreamReader.Close();
      }

      if (this.webServerStreamWriter != null)
      {
        this.webServerStreamWriter.Close();
      }

      if (this.httpWebServerSocket != null)
      {
        this.httpWebServerSocket.Close();
      }
    }

    #endregion


    #region Server header transfer

    public void ForwardRequestC2S(string requestMethod, string path, string httpVersion, byte[] clientNewlineBytes)
    {
      if (string.IsNullOrEmpty(requestMethod))
      {
        throw new Exception("MethodString is invalid");
      }

      if (string.IsNullOrEmpty(path))
      {
        throw new Exception("Path is invalid");
      }

      if (string.IsNullOrEmpty(httpVersion))
      {
        throw new Exception("HTTP version is invalid");
      }

      string requestString = $"{requestMethod} {path} {httpVersion}";
      byte[] requestByteArray = Encoding.UTF8.GetBytes(requestString);

      this.DumpstringDetails(requestMethod);
      this.DumpstringDetails(path);
      this.DumpstringDetails(httpVersion);

      this.webServerStreamWriter.Write(requestByteArray, 0, requestByteArray.Length);
      this.webServerStreamWriter.Write(clientNewlineBytes, 0, clientNewlineBytes.Length);
      this.webServerStreamWriter.Flush();
    }


    public void ForwardHeadersC2S(Dictionary<string, List<string>> clientRequestHeaders, byte[] clientNewlineBytes)
    {
      byte[] headerByteArray;
      var headerString = string.Empty;

      if (clientRequestHeaders == null || clientRequestHeaders.Keys.Count <= 0)
      {
        throw new Exception("Request headers are invalid");
      }

      // Send headers to server
      foreach (var tmpHeaderKey in clientRequestHeaders.Keys)
      {
        foreach (var headerValue in clientRequestHeaders[tmpHeaderKey])
        {
          headerString = $"{tmpHeaderKey}: {headerValue}";
          headerByteArray = Encoding.UTF8.GetBytes(headerString);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ForwardHeadersC2S(): Header Client2Server: {0}", headerString);
          this.webServerStreamWriter.Write(headerByteArray, 0, headerByteArray.Length);
          this.webServerStreamWriter.Write(clientNewlineBytes, 0, clientNewlineBytes.Length);
        }
      }

      // Send empty line to server to signalize "End of headerByteArray"
      this.webServerStreamWriter.Write(clientNewlineBytes, 0, clientNewlineBytes.Length);
      this.webServerStreamWriter.Flush();
    }


    public void ReadServerStatusLine(RequestObj requestObj)
    {
      string[] headerSplitter = new string[3];
      requestObj.ServerResponseObj.StatusLine = this.webServerStreamReader.ReadServerStatusLine(false);

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ReadServerStatusLine(): StatusLine={0}", requestObj.ServerResponseObj.StatusLine.StatusLine);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ReadServerStatusLine(): NewlineType={0}", requestObj.ServerResponseObj.StatusLine.NewlineType);

      // Evaluate response status line
      headerSplitter = requestObj.ServerResponseObj.StatusLine.StatusLine.Split(new char[] { ' ', '\t' }, 3);
      requestObj.ServerResponseObj.StatusLine.HttpVersion = headerSplitter[0];
      requestObj.ServerResponseObj.StatusLine.StatusCode = headerSplitter[1];
      requestObj.ServerResponseObj.StatusLine.StatusDescription = headerSplitter[2];
    }


    public void ReadServerResponseHeaders(ServerResponse serverResponseMetaDataObj)
    {
      string[] headerTuple = new string[2];
      string key = string.Empty;
      string value = string.Empty;
      string dataLine = string.Empty;

      dataLine = this.webServerStreamReader.ReadLine(false);

      while (dataLine.Length > 0)
      {
        if (!dataLine.Contains(":"))
        {
          throw new ProxyErrorException("The server response header was invalid");
        }

        headerTuple = dataLine.Split(new char[] { ':' }, 2);
        key = headerTuple[0].Trim();
        value = headerTuple[1].Trim();

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ReadServerResponseHeaders(): Adding headerByteArray \"{0}\" with value \"{1}\" ", key, value);

        // If it does not exist yet create a Server response HTTP header collection container
        if (!serverResponseMetaDataObj.ResponseHeaders.ContainsKey(key))
        {
          serverResponseMetaDataObj.ResponseHeaders.Add(key, new List<string>());
        }

        if (key.ToLower() == "connection" && value.ToLower() == "keep-alive")
        {
          this.requestObj.IsServerKeepAlive = true;
        }
        else if (key.ToLower() == "connection" && value.ToLower() == "close")
        {
          this.requestObj.IsServerKeepAlive = false;
        }

        serverResponseMetaDataObj.ResponseHeaders[key].Add(value);
        dataLine = this.webServerStreamReader.ReadLine(false);
      }

      // Parse Client request content type
      try
      {
        serverResponseMetaDataObj.ContentTypeEncoding = this.DetermineServerResponseContentTypeEncoding(serverResponseMetaDataObj.ResponseHeaders);
      }
      catch (ProxyWarningException pex)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "TcpClientBase.ReadServerResponseHeaders(Exception): Could not determine content type: {0}", pex.Message);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "TcpClientBase.ReadServerResponseHeaders(Exception): Setting default content type=text/html, charset=UTF-8");

        serverResponseMetaDataObj.ContentTypeEncoding.ContentType = "text/html";
        serverResponseMetaDataObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
        serverResponseMetaDataObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.GetEncoding(serverResponseMetaDataObj.ContentTypeEncoding.ContentCharSet);
      }

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ReadServerResponseHeaders(): Server response content type: {0}, {1}", serverResponseMetaDataObj.ContentTypeEncoding.ContentType, serverResponseMetaDataObj.ContentTypeEncoding.ContentCharSet);

      // Parse Client request content length
      this.DetermineServerResponseContentLength(serverResponseMetaDataObj);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ReadServerResponseHeaders(): Server response content length: {0}", serverResponseMetaDataObj.ContentLength);
    }

    #endregion


    #region Client header transfer

    public void ForwardStatusLineS2C(ServerResponseStatusLine serverResponseStatusLine)
    {
      string statusLineStr = $"{serverResponseStatusLine.HttpVersion} {serverResponseStatusLine.StatusCode} {serverResponseStatusLine.StatusDescription}";
      byte[] statusLineByteArr = Encoding.UTF8.GetBytes(statusLineStr);

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.ForwardStatusLineS2C(): statusLineStr: |{0}|", statusLineStr);
      this.clientStreamWriter.Write(statusLineByteArr, 0, statusLineByteArr.Length);
      this.clientStreamWriter.Write(serverResponseStatusLine.NewlineBytes, 0, serverResponseStatusLine.NewlineBytes.Length);
    }


    public void ForwardHeadersS2C(Dictionary<string, List<string>> serverResponseHeaders, byte[] serverNewlineBytes)
    {
      var header = string.Empty;
      byte[] headerByteArr;

      foreach (var tmpHeaderKey in serverResponseHeaders.Keys)
      {
        foreach (var headerValue in serverResponseHeaders[tmpHeaderKey])
        {
          header = $"{tmpHeaderKey}: {headerValue}";
          headerByteArr = Encoding.UTF8.GetBytes(header);
          this.clientStreamWriter.Write(headerByteArr, 0, headerByteArr.Length);
          this.clientStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
          this.clientStreamWriter.Flush();
        }
      }

      // Send empty line to server to signalize "End of headerByteArray"
      this.clientStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      this.clientStreamWriter.Flush();
    }

    #endregion


    #region Client/Server data transfer

    public int RelayDataC2S(bool mustBeProcessed, SniffedDataChunk sniffedDataChunk)
    {
      int noRelayedBytes = 0;
      byte[] buffer = new byte[MaxBufferSize];

      // 1. No data to relay/process
      if (this.requestObj.ProxyDataTransmissionModeC2S == DataTransmissionMode.NoDataToTransfer)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): DataTransmissionMode.NoDataToTransfer");

      // 2.0 Unknow amount of data chunks is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Transfer-Encoding" was set
      }
      else if (this.requestObj.ProxyDataTransmissionModeC2S == DataTransmissionMode.Chunked)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): DataTransmissionMode.Chunked, processed:false");
        noRelayedBytes = this.ForwardChunkedDataToPeerChunked(
          this.clientStreamReader,
          this.webServerStreamWriter,
          this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ClientRequestObj.RequestLine.NewlineBytes,
          sniffedDataChunk,
          mustBeProcessed);




      // 2.1 Unknow amount of data chunks is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Transfer-Encoding" was set
      }
      else if (this.requestObj.ProxyDataTransmissionModeC2S == DataTransmissionMode.FixedContentLength)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): DataTransmissionMode.ContentLength, processed:false");
        noRelayedBytes = this.ForwardNonchunkedDataToPeerNonChunked(
          this.clientStreamReader,
          this.webServerStreamWriter,
          this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ClientRequestObj.ContentLength,
          sniffedDataChunk,
          mustBeProcessed);


      // 2.2 Unknow amount of data chunks is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Transfer-Encoding" was set
      }
      else if (this.requestObj.ProxyDataTransmissionModeC2S == DataTransmissionMode.ReadOneLine)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): DataTransmissionMode.ReadOneLine, processed:false");
        this.ForwardSingleLineToPeer(
          this.clientStreamReader,
          this.webServerStreamWriter,
          this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ClientRequestObj.RequestLine.NewlineBytes,
          sniffedDataChunk,
          mustBeProcessed);



      // 4 Predefined amount of data is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Content-Length" was defined
      }
      else if (this.requestObj.ProxyDataTransmissionModeC2S == DataTransmissionMode.RelayBlindly)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): DataTransmissionMode.ContentLength, ContentLength:{0}, processed:true", this.requestObj.ClientRequestObj.ContentLength);
        this.BlindlyRelayData(this.clientStreamReader, this.webServerStreamWriter, sniffedDataChunk);

 

      // 5 This state actually should never happen! 
      //   I'll decide later what to do after it happened
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataC2S(): ContentLength:{0}, processed:false", this.requestObj.ClientRequestObj.ContentLength);
        noRelayedBytes = this.ForwardNonchunkedDataToPeerNonChunked(
          this.clientStreamReader,
          this.webServerStreamWriter,
          this.requestObj.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ClientRequestObj.ContentLength,
          null,
          false);
      }

      return noRelayedBytes;
    }


    public int RelayDataS2C(bool mustBeProcessed)
    {
      int noRelayedBytes = 0;
      byte[] buffer = new byte[MaxBufferSize];

      // 1. No data to relay/process
      if (this.requestObj.ProxyDataTransmissionModeS2C == DataTransmissionMode.NoDataToTransfer)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataS2C(): DataTransmissionMode.NoDataToTransfer");

      // 2.0 Unknow amount of data chunks is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Transfer-Encoding" was set
      }
      else if (this.requestObj.ProxyDataTransmissionModeS2C == DataTransmissionMode.Chunked)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataS2C(): DataTransmissionMode.Chunked, processed:false");
        noRelayedBytes = this.ForwardChunkedDataToPeerChunked(
          this.webServerStreamReader,
          this.clientStreamWriter,
          this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ServerResponseObj.StatusLine.NewlineBytes,
          null,
          mustBeProcessed);


      // 2.1 Unknow amount of data chunks is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Transfer-Encoding" was set
      }
      else if (this.requestObj.ProxyDataTransmissionModeS2C == DataTransmissionMode.FixedContentLength)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataS2C(): DataTransmissionMode.ContentLength, processed:false");
        noRelayedBytes = this.ForwardNonchunkedDataToPeerChunked(
          this.webServerStreamReader,
          this.clientStreamWriter,
          this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ServerResponseObj.ContentLength,
          this.requestObj.ServerResponseObj.StatusLine.NewlineBytes,
          null,
          mustBeProcessed);


      // 4 Predefined amount of data is transferred from the tcpClient to the peer system because
      // -   HTTP headerByteArray "Content-Length" was defined
      }
      else if (this.requestObj.ProxyDataTransmissionModeS2C == DataTransmissionMode.RelayBlindly)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataS2C(): DataTransmissionMode.RelayBlindly, ContentLength:{0}, processed:true", this.requestObj.ServerResponseObj.ContentLength);
        noRelayedBytes = this.BlindlyRelayData(this.webServerStreamReader, this.clientStreamWriter);



      // 5 This state actually should never happen! 
      //   I'll decide later what to do after it happened
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClienBase.RelayDataS2C(): ContentLength:{0}, processed:false", this.requestObj.ServerResponseObj.ContentLength);
        noRelayedBytes = this.ForwardNonchunkedDataToPeerNonChunked(
          this.webServerStreamReader,
          this.clientStreamWriter,
          this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding,
          this.requestObj.ServerResponseObj.ContentLength,
          null,
          false);
      }

      return noRelayedBytes;
    }

    #endregion

    #endregion


    #region PUBLIC

    public TcpClientBase(RequestObj requestObj, int remoteTcpPort) :
      base(requestObj)
    {
      this.requestObj = requestObj;
      this.remoteTcpPort = remoteTcpPort;
    }

    #region Client side

    #endregion


    #endregion


    #region PRIVATE

    private void DumpstringDetails(string data)
    {
      if (string.IsNullOrEmpty(data))
      {
        return;
      }

      string hexResult = this.StringToHex(data);
      try
      {
        hexResult = hexResult.Trim();
      }
      catch
      {
      }

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.DumpstringDetails():  |{0}| |{1}|", data, hexResult);
    }


    private void DetermineServerResponseContentLength(ServerResponse serverResponseMetaDataObj)
    {
      try
      {
        if (serverResponseMetaDataObj.ResponseHeaders.ContainsKey("Content-Length"))
        {
          string contentLen = serverResponseMetaDataObj.ResponseHeaders["Content-Length"][0];
          serverResponseMetaDataObj.ContentLength = int.Parse(contentLen);
        }
        else
        {
          serverResponseMetaDataObj.ContentLength = 0;
        }
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Error, "TcpClientBase.ReceiveServerResponsetHeaders(EXCEPTION/1): {0}", ex.Message);
        serverResponseMetaDataObj.ContentLength = 0;
      }
    }


    private DataContentTypeEncoding DetermineServerResponseContentTypeEncoding(Dictionary<string, List<string>> headers)
    {
      DataContentTypeEncoding contentTypeEncoding = new DataContentTypeEncoding();

      if (headers == null)
      {
        throw new ProxyWarningException("The headers list is invalid");
      }

      if (!headers.ContainsKey("Content-Type"))
      {
        throw new ProxyWarningException("The content type headerByteArray is invalid");
      }

      if (headers["Content-Type"].Count <= 0)
      {
        throw new ProxyWarningException("The content type headerByteArray is invalid");
      }

      if (string.IsNullOrEmpty(headers["Content-Type"][0].ToString()))
      {
        throw new ProxyWarningException("The content type headerByteArray is invalid");
      }

      // If there is no content type headerByteArray set the default values
      if (!headers.ContainsKey("Content-Type") ||
          string.IsNullOrEmpty(headers["Content-Type"][0].ToString()))
      {
        contentTypeEncoding.ContentType = "text/html";
        contentTypeEncoding.ContentCharSet = "UTF-8";
        contentTypeEncoding.ContentCharsetEncoding = Encoding.GetEncoding(contentTypeEncoding.ContentCharSet);

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.DetermineClientRequestContentTypeEncoding(): No Content-Type header found: text/html, UTF-8");
        return contentTypeEncoding;
      }

      // Parse the server response content type
      try
      {
        string contentType = headers["Content-Type"][0].ToString();

        if (contentType.Contains(";"))
        {
          string[] splitter = contentType.Split(new char[] { ';' }, 2);
          contentTypeEncoding.ContentType = splitter[0];
          contentTypeEncoding.ContentCharSet = this.DetermineContentCharSet(splitter[1]);
          contentTypeEncoding.ContentCharsetEncoding = Encoding.GetEncoding(contentTypeEncoding.ContentCharSet);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.DetermineClientRequestContentTypeEncoding(): Content-Type/Charset header found: {0}, {1}", contentTypeEncoding.ContentType, contentTypeEncoding.ContentCharSet);
        }
        else
        {
          contentTypeEncoding.ContentType = contentType;
          contentTypeEncoding.ContentCharSet = "UTF-8";
          contentTypeEncoding.ContentCharsetEncoding = Encoding.GetEncoding(contentTypeEncoding.ContentCharSet);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.DetermineClientRequestContentTypeEncoding(): Content-Type (noCharset) header found: {0}, {1}", contentTypeEncoding.ContentType, contentTypeEncoding.ContentCharSet);
        }
      }
      catch (Exception ex)
      {
        contentTypeEncoding.ContentType = "text/html";
        contentTypeEncoding.ContentCharSet = "UTF-8";
        contentTypeEncoding.ContentCharsetEncoding = Encoding.GetEncoding(contentTypeEncoding.ContentCharSet);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientBase.DetermineClientRequestContentTypeEncoding(Exception): text/html, UTF-8 {0}", ex.Message);
      }

      return contentTypeEncoding;
    }


    private string DetermineContentCharSet(string httpContentTypeHeader)
    {
      string determinedCharSet = "UTF-8";

      if (string.IsNullOrEmpty(httpContentTypeHeader))
      {
        throw new Exception("The char set headerByteArray is invalid");
      }

      httpContentTypeHeader = httpContentTypeHeader.Trim();
      if (Regex.Match(httpContentTypeHeader, @"^charset\s*=", RegexOptions.IgnoreCase).Success)
      {
        string[] splitter = httpContentTypeHeader.Split(new char[] { '=' }, 2);
        determinedCharSet = splitter[1];
      }

      return determinedCharSet;
    }


    private string StringToHex(string hexstring)
    {
      var sb = new StringBuilder();
      foreach (char t in hexstring)
      {
        sb.Append(Convert.ToInt32(t).ToString("x") + " ");
      }

      return sb.ToString();
    }

    #endregion

  }
}
