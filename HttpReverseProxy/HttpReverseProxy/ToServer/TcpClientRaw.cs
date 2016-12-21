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

    private const int MaxBufferSize = 4096;
    private RequestObj requestObj;

    #endregion


    #region PUBLIC

    public TcpClientRaw(RequestObj requestObj)
    {
      this.requestObj = requestObj;
    }

    #endregion


    #region NonProcessed

    public int ForwardChunkedNonprocessedDataToPeer(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      int blockSize = 0;
      int chunkCounter = 0;

      while (true)
      {
        // Read chunk size
        string chunkLenStr = inputStreamReader.ReadLine(false);

        // Break out of the loop if it is the last data packet
        if (string.IsNullOrEmpty(chunkLenStr))
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedNonprocessedDataToPeer(): chunkLenStr isNullOrEmpty!!!");
          break;
        }

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedNonprocessedDataToPeer(): ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
        blockSize = int.Parse(chunkLenStr, System.Globalization.NumberStyles.HexNumber);

        if (blockSize > 0)
        {
          this.RelayChunk(inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, serverNewlineBytes, sniffedDataChunk);
          noBytesTransferred += blockSize;

          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedNonprocessedDataToPeer(): blockSize > 0: ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
        }
        else if (blockSize == 0 || chunkLenStr == "0")
        {
          this.RelayChunk(inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, serverNewlineBytes, sniffedDataChunk);
          outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
          outputStreamWriter.Flush();
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedNonprocessedDataToPeer(): blockSize == 0: ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
          break;
        }
        else
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedNonprocessedDataToPeer(): WOOPS!");
        }

        chunkCounter++;
      }

      return noBytesTransferred;
    }


    public int ForwardNonchunkedNonprocessedDataToPeer(MyBinaryReader dataSenderStream, BinaryWriter dataRecipientStream, int transferredContentLength, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      byte[] buffer = new byte[transferredContentLength];
      int totalTransferredBytes = 0;
      int bytesRead = 0;


      while (totalTransferredBytes < transferredContentLength)
      {
        // Read data from peer 1
        int maxDataToTransfer = transferredContentLength - totalTransferredBytes;
        bytesRead = dataSenderStream.Read(buffer, 0, maxDataToTransfer);

        if (bytesRead <= 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA), No data to transfer");
          break;
        }

        // Write data to peer 2
        dataRecipientStream.Write(buffer, 0, bytesRead);
        dataRecipientStream.Flush();
        noBytesTransferred += bytesRead;

        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(buffer, bytesRead);
        }

        totalTransferredBytes += bytesRead;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA, TodalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", buffer.Length, bytesRead, totalTransferredBytes);
      }

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA): Total amount of transferred data={0}", totalTransferredBytes);
      return noBytesTransferred;
    }


    public int ForwardSingleLineNonprocessedDataToPeer(MyBinaryReader clientStreamReader, BinaryWriter webServerStreamWriter, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      byte[] clientData = clientStreamReader.ReadBinaryLine();

      if (clientData != null && clientData.Length > 0)
      {
        webServerStreamWriter.Write(clientData, 0, clientData.Length);
        noBytesTransferred += clientData.Length;

        // If a sniffer data chunk object is defined write application data to it
        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(clientData, clientData.Length);
        }

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData.Length:{0}", clientData.Length);
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData:NULL");
      }

      return noBytesTransferred;
    }


    public int BlindlyRelayData(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, SniffedDataChunk sniffedDataChunk = null)
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
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "BlindlyRelayData(): FragmentNo:{0} bytesTransferred:{1}", chunkCounter, bytesRead);
      }

      return noBytesTransferred;
    }

    #endregion


    #region Processed

    public int ForwardChunkedProcessedDataChunks(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, Encoding contentCharsetEncoding, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      int blockSize = 0;
      int chunkCounter = 0;
      string previousChunkLen = "00";

      while (true)
      {
        chunkCounter += 1;

        // Read chunk size
        string chunkLenStr = inputStreamReader.ReadLine(false);

        // Break out of the loop if it is the last data packet
        if (string.IsNullOrEmpty(chunkLenStr))
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedProcessedDataChunks(): chunkLenStr isNullOrEmpty!!!");
          break;
        }

        blockSize = int.Parse(chunkLenStr, System.Globalization.NumberStyles.HexNumber);
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedProcessedDataChunks(): ChunkNo={0}: previousChunkLen=0x{1} ChunkLength=0x{2}", chunkCounter, previousChunkLen, chunkLenStr);

        if (blockSize > 0)
        {
          this.ProcessAndRelayChunk(inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, contentCharsetEncoding, serverNewlineBytes);
          noBytesTransferred += blockSize;
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedProcessedDataChunks(): blockSize > 0: ChunkNo={0} chunkLenStr.Length={1}, Content=|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
        }
        else if (blockSize == 0 || chunkLenStr == "0")
        {
          this.ProcessAndRelayChunk(inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, contentCharsetEncoding, serverNewlineBytes);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedProcessedDataChunks(): blockSize == 0: ChunkNo={0} chunkLenStr.Length={1}, Content=|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);

          break;
        }
        else
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardChunkedProcessedDataChunks(): WOOPS!");
        }

        previousChunkLen = chunkLenStr;
      }

      return noBytesTransferred;
    }


    public int ForwardNonchunkedProcessedDataToPeer(MyBinaryReader dataSenderStream, BinaryWriter dataRecipientStream, int transferredContentLength, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      MemoryStream memStream = new MemoryStream();
      byte[] buffer = new byte[transferredContentLength];
      int totalTransferredBytes = 0;
      int bytesRead = 0;

      while (totalTransferredBytes < transferredContentLength)
      {
        // Read data from peer 1
        int maxDataToTransfer = transferredContentLength - totalTransferredBytes;
        bytesRead = dataSenderStream.Read(buffer, 0, maxDataToTransfer);

        if (bytesRead <= 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardNonchunkedProcessedDataToPeer(2:DATA), No data to transfer");
          break;
        }

        // Write data to memory stream
        memStream.Write(buffer, 0, bytesRead);

        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(buffer, bytesRead);
        }

        totalTransferredBytes += bytesRead;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardNonchunkedProcessedDataToPeer(2:DATA, TodalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", buffer.Length, bytesRead, totalTransferredBytes);
      }

      // SSL strip server data packet
      byte[] dataPacket = memStream.ToArray();
      if (dataPacket.Length != transferredContentLength)
      {
        throw new Exception("The announced content length and the amount of received data are not the same");
      }

      // Encode received bytes to the announced format
      int preProcessingPacketSize = dataPacket.Length;
      string dataBlockString = this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding.GetString(dataPacket);
      DataPacket serverDataPacket = new DataPacket(dataPacket, this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding);
      Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataPacket);

      // Send data packet to recipient
      dataRecipientStream.Write(serverDataPacket.ContentData, 0, serverDataPacket.ContentData.Length);
      dataRecipientStream.Flush();
      noBytesTransferred += serverDataPacket.ContentData.Length;
      Logging.Instance.LogMessage(
                                  this.requestObj.Id,
                                  this.requestObj.ProxyProtocol,
                                   Loglevel.DEBUG,
                                  "TcpClientRaw.ForwardNonchunkedProcessedDataToPeer(): Data successfully relayed to client. ContentDataSize:{0})",
                                  serverDataPacket.ContentData.Length);

      return noBytesTransferred;
    }


    public int ForwardSingleLineProcessedDataToPeer(MyBinaryReader clientStreamReader, BinaryWriter webServerStreamWriter, SniffedDataChunk sniffedDataChunk = null)
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

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData.Length:{0}", clientData.Length);
      }
      else
      {
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ForwardSingleLineNonprocessedDataToPeer(): clientData:NULL");
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
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "Chunked.ReceiveChunk(0:MaxLen:{0}): Receiving fragment {1} from: Client -> Server ({2} buffer, totalBytesReceived:{3}, totalBytesToRead:{4})", buffer.Length, chunkFragmentCounter, bytesRead, totalBytesReceived, totalBytesToRead);
          break;
        }
        else
        {
          totalBytesReceived += bytesRead;
          memStream.Write(buffer, 0, bytesRead);
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "Chunked.ReceiveChunk(1:MaxLen:{0}): Receiving fragment {1} from: Client -> Server ({2} buffer, totalBytesReceived:{3}, totalBytesToRead:{4})", buffer.Length, chunkFragmentCounter, bytesRead, totalBytesReceived, totalBytesToRead);
        }

        maxInputLen -= bytesRead;
        chunkFragmentCounter++;
      }

      byte[] fullDataChunk = memStream.ToArray();

      return fullDataChunk;
    }


    private void RelayChunk(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, int chunkSize, string chunkSizeHexString, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
    {
      int bytesRead = 0;
      int dataVolume = 0;

      // Write packet size to server data stream
      byte[] chunkSizeDeclaration = Encoding.UTF8.GetBytes(chunkSizeHexString);
      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      byte[] dataBlock = this.ReceiveChunk(chunkSize, inputStreamReader);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.RelayChunk(): ChunkSize:{0}, binaryDataBlock.Length:{1}", chunkSize, dataBlock.Length);

      if (chunkSize != dataBlock.Length)
      {
        throw new Exception("Server did not send all data");
      }

      // Write application data to server data stream
      outputStreamWriter.Write(dataBlock, 0, chunkSize);

      // If a sniffer data chunk object is defined write application data to it
      if (sniffedDataChunk != null)
      {
        sniffedDataChunk.AppendData(dataBlock, dataBlock.Length);
      }

      // Send trailing CRLF to finish chunk transmission
      inputStreamReader.ReadLine();
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      outputStreamWriter.Flush();
      dataVolume += bytesRead;
    }


    private void ProcessAndRelayChunk(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, int chunkSize, string chunkSizeHexString, Encoding contentCharsetEncoding, byte[] serverNewlineBytes)
    {
      // Read all bytes from server stream
      byte[] binaryDataBlock = this.ReceiveChunk(chunkSize, inputStreamReader);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ProcessAndRelayChunk(): ChunkSize:{0}, binaryDataBlock.Length:{1}", chunkSize, binaryDataBlock.Length);

      if (chunkSize != binaryDataBlock.Length)
      {
        throw new Exception("The announced content length and the amount of received data are not the same");
      }

      // Encode received bytes to the announced format
      string dataBlockString = contentCharsetEncoding.GetString(binaryDataBlock);
      DataPacket serverDataPacket = new DataPacket(binaryDataBlock, contentCharsetEncoding);

      // Send chunk size to recepient
      string chunkSizeHexStringTmp = serverDataPacket.ContentData.Length.ToString("x");
      byte[] chunkSizeDeclaration = contentCharsetEncoding.GetBytes(chunkSizeHexStringTmp);
      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataPacket.ContentData, 0, serverDataPacket.ContentData.Length);

      // Send trailing newline to finish chunk transmission
      inputStreamReader.ReadLine();
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      outputStreamWriter.Flush();

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.DEBUG, "TcpClientRaw.ProcessAndRelayChunk(): Transferred {0}/{1} bytes from SERVER -> CLIENT: ", chunkSize, serverDataPacket.ContentData.Length);
    }

    #endregion

  }
}
