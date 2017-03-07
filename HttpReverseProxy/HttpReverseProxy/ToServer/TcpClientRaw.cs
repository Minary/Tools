namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.IO;
  using System.Text;
  using System.Text.RegularExpressions;


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





    #region NG

    public int ForwardNonchunkedDataToPeer2(
          MyBinaryReader inputStreamReader,
          BinaryWriter outputStreamWriter,
          Encoding contentCharsetEncoding,
          int transferredContentLength,
      SniffedDataChunk sniffedDataChunk,
      bool mustBeProcessed)
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
        bytesRead = inputStreamReader.Read(buffer, 0, maxDataToTransfer);

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
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer2(2:DATA, TodalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", buffer.Length, bytesRead, totalTransferredBytes);
      }

      byte[] dataPacket = memStream.ToArray();
      if (dataPacket.Length != transferredContentLength)
      {
        throw new Exception("The announced content length and the amount of received data are not the same");
      }

      // Encode received bytes to the announced format
      DataChunk serverDataChunk = new DataChunk(dataPacket, this.requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding);

      if (mustBeProcessed == true)
      {
        Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataChunk);
      }

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentData.Length);
      outputStreamWriter.Flush();
      noBytesTransferred += serverDataChunk.ContentData.Length;
      Logging.Instance.LogMessage(
                                  this.requestObj.Id,
                                  this.requestObj.ProxyProtocol,
                                   Loglevel.Debug,
                                  "TcpClientRaw.ForwardNonchunkedDataToPeer2(): Data successfully relayed to client. ContentDataSize:{0})",
                                  serverDataChunk.ContentData.Length);

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedDataToPeer2(2:DATA): Total amount of transferred data={0}", totalTransferredBytes);
      return noBytesTransferred;
    }


    public int ForwardChunkedDataToPeer2(
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


    public int ForwardSingleLineToPeer2(
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


 public int ForwardAndInjectChunkedNonprocessedDataToPeer(PluginInstruction pluginInstruction, MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
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
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardAndInjectChunkedNonprocessedDataToPeer(): chunkLenStr isNullOrEmpty!!!");
          break;
        }

        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardAndInjectChunkedNonprocessedDataToPeer(): ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
        blockSize = int.Parse(chunkLenStr, System.Globalization.NumberStyles.HexNumber);

        // If the announced block size is > 0 analyze the data block
        // and if the trigger tag was found inject the code.
        // Subsequently relay the data block to the client system
        // and continue with the next block
        if (blockSize > 0)
        {
          this.InjectAndRelayChunk(pluginInstruction, inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, serverNewlineBytes, sniffedDataChunk);
          noBytesTransferred += blockSize;

          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardAndInjectChunkedNonprocessedDataToPeer(): blockSize > 0: ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);

        // If the announced block size is 0
        // break out of the relay loop
        }
        else if (blockSize == 0 || chunkLenStr == "0")
        {
          this.RelayChunk(inputStreamReader, outputStreamWriter, blockSize, chunkLenStr, serverNewlineBytes, sniffedDataChunk);
          outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
          outputStreamWriter.Flush();
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardAndInjectChunkedNonprocessedDataToPeer(): blockSize == 0: ChunkNo:{0} chunkLenStr.Length:{1}, Content:|0x{2}|", chunkCounter, chunkLenStr.Length, chunkLenStr);
          break;
        }
        else
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardAndInjectChunkedNonprocessedDataToPeer(): WOOPS!");
          break;
        }

        chunkCounter++;
      }

      return noBytesTransferred;
    }

 
 public int ForwardAndInjectNonChunkedNonprocessedDataToPeer(PluginInstruction pluginInstruction, MyBinaryReader dataSenderStream, BinaryWriter dataRecipientStream, int transferredContentLength, SniffedDataChunk sniffedDataChunk = null)
    {
      int noBytesTransferred = 0;
      byte[] dataBlock = new byte[transferredContentLength];
      int totalTransferredBytes = 0;
      int bytesRead = 0;

      while (totalTransferredBytes < transferredContentLength)
      {
        // Read data from peer 1
        int maxDataToTransfer = transferredContentLength - totalTransferredBytes;
        bytesRead = dataSenderStream.Read(dataBlock, 0, maxDataToTransfer);

        if (bytesRead <= 0)
        {
          Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA), No data to transfer");
          break;
        }

        // 2. Decode bytes to UTF8
        string readableData = Encoding.UTF8.GetString(dataBlock);
        MatchCollection matches = Regex.Matches(readableData, pluginInstruction.InstructionParameters.DataDict["tagRegex"]);
        if (pluginInstruction.InstructionParameters.DataDict.ContainsKey("tagRegex") &&
            pluginInstruction.InstructionParameters.DataDict["tagRegex"].Length > 0 &&
            matches.Count > 0)
        {
          byte[] tmpDataBlock;
          string foundTag = matches[0].Groups[1].Value;
          string foundTagEscaped = Regex.Escape(foundTag);
          string replacementData = pluginInstruction.InstructionParameters.DataDict["data"];

          if (pluginInstruction.InstructionParameters.DataDict["position"] == "before")
          {
            replacementData = replacementData + " " + foundTag;
          }
          else
          {
            replacementData = foundTag + " " + replacementData;
          }

          readableData = Regex.Replace(readableData, foundTagEscaped, replacementData);
          tmpDataBlock = Encoding.UTF8.GetBytes(readableData);
          Logging.Instance.LogMessage(
            this.requestObj.Id,
            this.requestObj.ProxyProtocol,
            Loglevel.Info,
            "NonChunked.ForwardAndInjectNonChunkedNonprocessedDataToPeer(): Tag \"{0}\" detected, content of \"{1}\" injected",
            pluginInstruction.InstructionParameters.DataDict["tag"],
            Path.GetFileName(pluginInstruction.InstructionParameters.DataDict["file"]));

          // Write data to peer 2
          dataRecipientStream.Write(tmpDataBlock, 0, tmpDataBlock.Length);
          dataRecipientStream.Flush();
          noBytesTransferred += tmpDataBlock.Length;
        }
        else
        {
          // Write data to peer 2
          dataRecipientStream.Write(dataBlock, 0, bytesRead);
          dataRecipientStream.Flush();
          noBytesTransferred += bytesRead;
        }

        if (sniffedDataChunk != null)
        {
          sniffedDataChunk.AppendData(dataBlock, bytesRead);
        }

        totalTransferredBytes += bytesRead;
        Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA, TodalDataToTransfer:{0}): Relaying data from: Client -> Server (bytesRead:{1} totalTransferredBytes:{2})", dataBlock.Length, bytesRead, totalTransferredBytes);
      }

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ForwardNonchunkedNonprocessedDataToPeer(2:DATA): Total amount of transferred data={0}", totalTransferredBytes);
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


    private void RelayChunk(MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, int chunkSize, string chunkSizeHexString, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
    {
      int bytesRead = 0;
      int dataVolume = 0;

      // Write packet size to server data stream
      byte[] chunkSizeDeclaration = Encoding.UTF8.GetBytes(chunkSizeHexString);
      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      byte[] dataBlock = this.ReceiveChunk(chunkSize, inputStreamReader);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.RelayChunk(): ChunkSize:{0}, binaryDataBlock.Length:{1}", chunkSize, dataBlock.Length);

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
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ProcessAndRelayChunk(): ChunkSize:{0}, binaryDataBlock.Length:{1}", chunkSize, binaryDataBlock.Length);

      if (chunkSize != binaryDataBlock.Length)
      {
        throw new Exception("The announced content length and the amount of received data are not the same");
      }

      // Encode received bytes to the announced format
      DataChunk serverDataChunk = new DataChunk(binaryDataBlock, contentCharsetEncoding);

      // Send chunk size to recepient
      string chunkSizeHexStringTmp = serverDataChunk.ContentData.Length.ToString("x");
      byte[] chunkSizeDeclaration = contentCharsetEncoding.GetBytes(chunkSizeHexStringTmp);
      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentData.Length);

      // Send trailing newline to finish chunk transmission
      inputStreamReader.ReadLine();
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      outputStreamWriter.Flush();

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.ProcessAndRelayChunk(): Transferred {0}/{1} bytes from SERVER -> CLIENT: ", chunkSize, serverDataChunk.ContentData.Length);
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
      DataChunk serverDataChunk = new DataChunk(binaryDataBlock, contentCharsetEncoding);

      // If response can be processed : do so.
      if (mustBeProcessed == true)
      {
        Lib.PluginCalls.PostServerDataResponse(this.requestObj, serverDataChunk);
      }

      // Send chunk size to recepient
      string chunkSizeHexStringTmp = serverDataChunk.ContentData.Length.ToString("x");
      byte[] chunkSizeDeclaration = contentCharsetEncoding.GetBytes(chunkSizeHexStringTmp);

      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

      // Send data packet to recipient
      outputStreamWriter.Write(serverDataChunk.ContentData, 0, serverDataChunk.ContentData.Length);

      // Send trailing newline to finish chunk transmission
      inputStreamReader.ReadLine();
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);
      outputStreamWriter.Flush();

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientRaw.RelayChunk2(): Transferred {0}/{1} bytes from SERVER -> CLIENT: ", announcedChunkSize, serverDataChunk.ContentData.Length);
      return totalBytesTransferred;
    }



    private void InjectAndRelayChunk(PluginInstruction pluginInstruction, MyBinaryReader inputStreamReader, BinaryWriter outputStreamWriter, int chunkSize, string chunkSizeHexString, byte[] serverNewlineBytes, SniffedDataChunk sniffedDataChunk = null)
    {
      int bytesRead = 0;
      int dataVolume = 0;

      // 1. Read data chunk
      byte[] dataBlock = this.ReceiveChunk(chunkSize, inputStreamReader);
      if (chunkSize != dataBlock.Length)
      {
        throw new Exception("Server did not send all data");
      }

      // 2. Decode bytes to UTF8
      string readableData = Encoding.UTF8.GetString(dataBlock);
      MatchCollection matches = Regex.Matches(readableData, pluginInstruction.InstructionParameters.DataDict["tagRegex"]);
      if (pluginInstruction.InstructionParameters.DataDict.ContainsKey("tagRegex") &&
          pluginInstruction.InstructionParameters.DataDict["tagRegex"].Length > 0 &&
          matches.Count > 0)
      {
        string foundTag = matches[0].Groups[1].Value;
        string foundTagEscaped = Regex.Escape(foundTag);
        string replacementData = pluginInstruction.InstructionParameters.DataDict["data"];

        if (pluginInstruction.InstructionParameters.DataDict["position"] == "before")
        {
          replacementData = replacementData + " " + foundTag;
        }
        else
        {
          replacementData = foundTag + " " + replacementData;
        }

        readableData = Regex.Replace(readableData, foundTagEscaped, replacementData);
        dataBlock = Encoding.UTF8.GetBytes(readableData);
        Logging.Instance.LogMessage(
          this.requestObj.Id,
          this.requestObj.ProxyProtocol,
          Loglevel.Info,
          "Chunked.InjectAndRelayChunk(): Tag \"{0}\" detected, content of \"{1}\" injected",
          pluginInstruction.InstructionParameters.DataDict["tag"],
          Path.GetFileName(pluginInstruction.InstructionParameters.DataDict["file"]));
      }

      // Write packet size to server data stream
      byte[] chunkSizeDeclaration = Encoding.UTF8.GetBytes(chunkSizeHexString);
      outputStreamWriter.Write(chunkSizeDeclaration, 0, chunkSizeDeclaration.Length);
      outputStreamWriter.Write(serverNewlineBytes, 0, serverNewlineBytes.Length);

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

    #endregion

  }
}
