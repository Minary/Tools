namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.IO;
  using System.Text;


  public class TcpClientRaw
  {

    #region MEMBERS

    private const int MaxBufferSize = 8192;
    private RequestObj requestObj;

    #endregion


    #region PUBLIC

    public TcpClientRaw(RequestObj requestObj)
    {
      this.requestObj = requestObj;
    }


    public int ForwardNonchunkedDataToPeerNonChunked(
          MyBinaryReader inputStreamReader,
          BinaryWriter outputStreamWriter,
          Encoding contentCharsetEncoding,
          int transferredContentLength,
          SniffedDataChunk sniffedDataChunk,
          bool mustBeProcessed)
    {
      int noBytesTransferred = 0;
      MemoryStream memStream = new MemoryStream();
      byte[] buffer = new byte[MaxBufferSize];
      int totalTransferredBytes = 0;
      int bytesRead = 0;

      while (totalTransferredBytes < transferredContentLength)
      {
        // Read data from peer 1
        int maxDataToTransfer = transferredContentLength - totalTransferredBytes;
        bytesRead = inputStreamReader.Read(buffer, 0, buffer.Length);

        if (bytesRead <= 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer2(2:DATA), No data to transfer");
          break;
        }

        // Write data to memory stream
        memStream.Write(buffer, 0, bytesRead);

        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(buffer, bytesRead);
        }

        totalTransferredBytes += bytesRead;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer2(2:DATA, TotalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", buffer.Length, bytesRead, totalTransferredBytes);
      }

      byte[] dataPacket = memStream.ToArray();
      //if (dataPacket.Length != MaxBufferSize)
      //{
      //  throw new Exception("The announced content length and the amount of received data are not the same");
      //}

      // Encode received bytes to the announced format
      DataChunk serverDataChunk = new DataChunk(dataPacket, dataPacket.Length, this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding);

      if (mustBeProcessed == true)
      {
        Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataChunk);
      }

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentDataLength);
      outputStreamWriter.Flush();
      noBytesTransferred += serverDataChunk.ContentDataLength;
      Logging.Instance.LogMessage(
                                  this.requestObj.Id,
                                  this.requestObj.ProxyProtocol,
                                   Loglevel.Debug,
                                  "TcpClientRaw.ForwardNonchunkedDataToPeer2(): Data successfully relayed to client. ContentDataSize:{0})",
                                  serverDataChunk.ContentDataLength);

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer2(2:DATA): Total amount of transferred data={0}", totalTransferredBytes);
      return noBytesTransferred;
    }


    public int ForwardNonchunkedDataToPeerChunked(
          MyBinaryReader inputStreamReader,
          BinaryWriter outputStreamWriter,
          Encoding contentCharsetEncoding,
          int transferredContentLength,
          byte[] serverNewlineBytes,
          SniffedDataChunk sniffedDataChunk,
          bool mustBeProcessed)
    {
      int noBytesTransferred = 0;
      byte[] buffer = new byte[MaxBufferSize];
      int totalTransferredBytes = 0;
      int bytesRead = 0;

      while (totalTransferredBytes < transferredContentLength)
      {
        // Read data from peer 1
        int maxDataToTransfer = transferredContentLength - totalTransferredBytes;
        bytesRead = inputStreamReader.Read(buffer, 0, buffer.Length);

        if (bytesRead <= 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer3(2:DATA), No data to transfer");
          break;
        }

        //
        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(buffer, bytesRead);
        }

        // Encode received bytes to the announced format
        DataChunk serverDataChunk = new DataChunk(buffer, bytesRead, this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding);

        if (mustBeProcessed == true)
        {
          Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataChunk);
        }

        // Send chunk size to recepient
        string chunkSizeHexStringTmp = serverDataChunk.ContentDataLength.ToString("x");
        byte[] chunkSizeDeclaration = contentCharsetEncoding.GetBytes(chunkSizeHexStringTmp);
        outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
        outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

        // Send data packet to recipient
        outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentDataLength);
        outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
        outputStreamWriter.Flush();

        noBytesTransferred += serverDataChunk.ContentDataLength;
        Logging.Instance.LogMessage(
                                    this.requestObj.Id,
                                    this.requestObj.ProxyProtocol,
                                     Loglevel.Debug,
                                    "TcpClientRaw.ForwardNonchunkedDataToPeer3(): Data successfully relayed to client. ContentDataSize:{0})",
                                    serverDataChunk.ContentDataLength);

        totalTransferredBytes += bytesRead;
//        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer3(2:DATA, TotalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", buffer.Length, bytesRead, totalTransferredBytes);
      }

      // Send trailing "0 length" chunk
      string chunkSizeZeroHexString = 0.ToString("x");
      byte[] chunkSizeZeroDeclaration = contentCharsetEncoding.GetBytes(chunkSizeZeroHexString);
      outputStreamWriter.Write(chunkSizeZeroDeclaration, 0, chunkSizeZeroDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer3(2:DATA): Total amount of transferred data={0}", totalTransferredBytes);
      return noBytesTransferred;
    }


    public int ForwardChunkedDataToPeerChunked(
      MyBinaryReader inputStreamReader,
      BinaryWriter outputStreamWriter,
      Encoding contentCharsetEncoding,
      byte[] serverNewlineBytes,
      SniffedDataChunk sniffedDataChunk,
      bool isProcessed) // <-- relevant for sslstrip and injectFile
    {
      int noBytesTransferred = 0;
      int noEffectivelyTransferredBytes = 0;
      int announcedChunkSize = 0;
      int chunkCounter = 0;
      string previousChunkLen = "00";

      while (true)
      {
        chunkCounter += 1;

        // Read chunk size
        string chunkLenStr = inputStreamReader.ReadLine(false);

        // Jump out of the loop if it is the last data packet
        if (string.IsNullOrEmpty(chunkLenStr))
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardChunkedDataToPeer2(): WOOPS! chunkLenStr isNullOrEmpty!!!");
          break;
        }

        announcedChunkSize = int.Parse(chunkLenStr, System.Globalization.NumberStyles.HexNumber);
        // If announced chunk size is invalid/<0 jump out of the loop
        if (announcedChunkSize < 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardChunkedDataToPeer2(): WOOPS! Invalid chunk size!!!");
          break;
        }

        // Receive announced data chunk from server
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardChunkedDataToPeer2(): ChunkNo={0}: previousChunkLen=0x{1} ChunkLength=0x{2}", chunkCounter, previousChunkLen, chunkLenStr);
        noEffectivelyTransferredBytes = this.RelayChunk2(inputStreamReader, outputStreamWriter, announcedChunkSize, contentCharsetEncoding, serverNewlineBytes, isProcessed);
        noBytesTransferred += noEffectivelyTransferredBytes;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardChunkedDataToPeer2(): blockSize > 0: ChunkNo={0} chunkLenStr.Length={1}, Content=|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
        previousChunkLen = chunkLenStr;

        // If chunk size is zero jump out of the loop
        if (announcedChunkSize == 0 || chunkLenStr == "0")
        {
          break;
        }
      }

      return noBytesTransferred;
    }


    public int ForwardSingleLineToPeer(
      MyBinaryReader clientStreamReader,
      BinaryWriter webServerStreamWriter,
      Encoding contentCharsetEncoding,
      byte[] serverNewlineBytes,
      SniffedDataChunk sniffedDataChunk,
      bool mustBeProcessed)
    {
      int noBytesTransferred = 0;
      byte[] clientData = clientStreamReader.ReadBinaryLine();

      if (clientData != null && clientData.Length > 0)
      {
        // Forward received data packets to peer
        webServerStreamWriter.Write(clientData, 0, clientData.Length);
        noBytesTransferred += clientData.Length;

        // If a sniffer data chunk object is defined write application data to it
        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(clientData, clientData.Length);
        }

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData.Length:{0}", clientData.Length);
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData:NULL");
      }

      return noBytesTransferred;
    }


    public int BlindlyRelayData(
      MyBinaryReader inputStreamReader, 
      BinaryWriter outputStreamWriter, 
      SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      int bytesRead = 0;
      int chunkCounter = 0;
      byte[] buffer = new byte[MaxBufferSize];

      while ((bytesRead = inputStreamReader.Read(buffer, 0, buffer.Length)) > 0)
      {
        // Forward received data packets to peer
        outputStreamWriter.Write(buffer, 0, bytesRead);
        noBytesTransferred += bytesRead;

        // If a sniffer data chunk object is defined write application data to it
        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(buffer, bytesRead);
        }

        chunkCounter++;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "BlindlyRelayData(): FragmentNo:{0} bytesTransferred:{1}", chunkCounter, bytesRead);
      }

      return noBytesTransferred;
    }

    #endregion
 

    #region PRIVATE

    private byte[] ReceiveChunk(int totalBytesToRead, MyBinaryReader dataSenderStream)
    {
      int bytesRead = 0;
      int totalBytesReceived = 0;
      int chunkFragmentCounter = 0;
      MemoryStream memStream = new MemoryStream();
      byte[] buffer = new byte[totalBytesToRead];
      int maxInputLen = totalBytesToRead;

      while (totalBytesReceived < totalBytesToRead &&
             (bytesRead = dataSenderStream.Read(buffer, 0, maxInputLen)) > 0)
      {
        if (totalBytesReceived + bytesRead >= totalBytesToRead)
        {
          int newPacketSize = bytesRead - ((totalBytesReceived + bytesRead) - totalBytesToRead);
          totalBytesReceived += newPacketSize;
          memStream.Write(buffer, 0, newPacketSize);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "Chunked.ReceiveChunk(0:MaxLen:{0}): Receiving fragment {1} from: Client -> Server ({2} buffer, totalBytesReceived:{3}, totalBytesToRead:{4})", buffer.Length, chunkFragmentCounter, bytesRead, totalBytesReceived, totalBytesToRead);
          break;
        }
        else
        {
          totalBytesReceived += bytesRead;
          memStream.Write(buffer, 0, bytesRead);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "Chunked.ReceiveChunk(1:MaxLen:{0}): Receiving fragment {1} from: Client -> Server ({2} buffer, totalBytesReceived:{3}, totalBytesToRead:{4})", buffer.Length, chunkFragmentCounter, bytesRead, totalBytesReceived, totalBytesToRead);
        }

        maxInputLen -= bytesRead;
        chunkFragmentCounter++;
      }

      byte[] fullDataChunk = memStream.ToArray();

      return fullDataChunk;
    }


    private int RelayChunk2(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, int announcedChunkSize, Encoding contentCharsetEncoding, byte[] serverNewlineBytes, bool mustBeProcessed)
    {
      int totalBytesTransferred = 0;

      // Read all bytes from server stream
      byte[] binaryDataBlock = this.ReceiveChunk(announcedChunkSize, inputStreamReader);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.RelayChunk2(): ChunkSize:{0}, binaryDataBlock.Length:{1}", announcedChunkSize, binaryDataBlock.Length);

      if (announcedChunkSize != binaryDataBlock.Length)
      {
        throw new Exception("The announced content length and the amount of received data are not the same");
      }

      // Encode received bytes to the announced format
      // string dataBlockString = contentCharsetEncoding.GetString(binaryDataBlock);
      DataChunk serverDataChunk = new DataChunk(binaryDataBlock, binaryDataBlock.Length, contentCharsetEncoding);

      // If response can be processed : do so.
      if (mustBeProcessed == true)
      {
        Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataChunk);
      }

      // Send chunk size to recepient
      string chunkSizeHexStringTmp = serverDataChunk.ContentDataLength.ToString("x");
      byte[] chunkSizeDeclaration = contentCharsetEncoding.GetBytes(chunkSizeHexStringTmp);

      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentDataLength);

      // Send trailing newline to finish chunk transmission
      inputStreamReader.ReadLine();
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      outputStreamWriter.Flush();

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.RelayChunk2(): Transferred {0}/{1} bytes from SERVER -> CLIENT: ", announcedChunkSize, serverDataChunk.ContentDataLength);
      return totalBytesTransferred;
    }

    #endregion

  }
}
