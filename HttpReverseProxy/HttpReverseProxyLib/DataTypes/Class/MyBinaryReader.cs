namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Class.Client;
  using HttpReverseProxyLib.DataTypes.Class.Server;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.IO;
  using System.Text;


  public class MyBinaryReader : BinaryReader
  {

    #region MEMBERS

    private const int BufferSize = 1024;
    private Encoding encoding;
    private Decoder decoder;
    private char[] lineBuffer = new char[BufferSize];
    private string clientConnectionId;

    #endregion


    #region PUBLIC

    public MyBinaryReader(Stream stream, int bufferSize, Encoding encoding, string clientConnectionId)
      : base(stream, encoding)
    {
      this.encoding = encoding;
      this.decoder = encoding.GetDecoder();
      this.clientConnectionId = clientConnectionId;

      //base.BaseStream.ReadTimeout = 10000;
      //base.BaseStream.WriteTimeout = 10000;
    }


    public ClientRequestLine ReadClientRequestLine(bool keepTrailingNewline = false)
    {
      bool carriageReturnDetected = false;
      ClientRequestLine clientRequestLine = new ClientRequestLine();
      StringBuilder result = new StringBuilder();
      bool foundEndOfLine = false;
      char currentChar;

      while (!foundEndOfLine)
      {
        try
        {
          currentChar = base.ReadChar();
        }
        catch (EndOfStreamException ex)
        {
          Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadClientRequestLine(EndOfStreamException): Client request header: {0}", ex.Message);

          if (result.Length == 0)
          {
            return null;
          }
          else
          {
            break;
          }
        }

        switch (currentChar)
        {
          case '\r':
            result.Append(currentChar);
            carriageReturnDetected = true;
            break;
          case '\n':
            result.Append(currentChar);
            foundEndOfLine = true;
            break;
          default:
            result.Append(currentChar);
            break;
        }
      }

      // Populate status line object
      clientRequestLine.RequestLine = result.ToString();
      clientRequestLine.NewlineType = carriageReturnDetected ? Newline.CRLF : Newline.LF;
      clientRequestLine.NewlineBytes = carriageReturnDetected ? new byte[] { 0x0D, 0x0A } : new byte[] { 0x0A };
      clientRequestLine.NewlineString = Encoding.UTF8.GetString(clientRequestLine.NewlineBytes);

      // Remove trailing newlines if required.
      if (!keepTrailingNewline)
      {
        clientRequestLine.RequestLine = clientRequestLine.RequestLine.TrimEnd();
      }

      return clientRequestLine;
    }


    public ServerResponseStatusLine ReadServerStatusLine(bool keepTrailingNewline = false)
    {
      bool carriageReturnDetected = false;
      ServerResponseStatusLine serverStatusLine = new ServerResponseStatusLine();
      StringBuilder result = new StringBuilder();
      bool foundEndOfLine = false;
      char currentChar;

      while (!foundEndOfLine)
      {
        try
        {
          currentChar = base.ReadChar();
        }
        catch (EndOfStreamException ex)
        {
          Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadServerStatusLine(EndOfStreamException): Client request header: {0}", ex.Message);

          if (result.Length == 0)
          {
            return null;
          }
          else
          {
            break;
          }
        }

        switch (currentChar)
        {
          case '\r':
            result.Append(currentChar);
            carriageReturnDetected = true;
            break;
          case '\n':
            result.Append(currentChar);
            foundEndOfLine = true;
            break;
          default:
            result.Append(currentChar);
            break;
        }
      }

      // Populate status line object
      serverStatusLine.StatusLine = result.ToString();
      serverStatusLine.NewlineType = carriageReturnDetected?Newline.CRLF:Newline.LF;
      serverStatusLine.NewlineBytes = carriageReturnDetected ? new byte[] { 0x0D, 0x0A } : new byte[] { 0x0A };
      serverStatusLine.NewlineString = Encoding.UTF8.GetString(serverStatusLine.NewlineBytes);

      // Remove trailing newlines if required.
      if (!keepTrailingNewline)
      {
        serverStatusLine.StatusLine = serverStatusLine.StatusLine.TrimEnd();
      }

      return serverStatusLine;
    }


    public string ReadLine(bool keepTrailingNewline = false)
    {
      StringBuilder result = new StringBuilder();
      bool foundEndOfLine = false;
      char currentChar;

      while (!foundEndOfLine)
      {
        try
        {
          currentChar = base.ReadChar();
        }
        catch (EndOfStreamException ex)
        {
          Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadLine(EndOfStreamException): Client request header: {0}", ex.Message);

          if (result.Length == 0)
          {
            return null;
          }
          else
          {
            break;
          }
        }

        switch (currentChar)
        {
          case '\r':
            result.Append(currentChar);
            break;
          case '\n':
            result.Append(currentChar);
            foundEndOfLine = true;
            break;
          default:
            result.Append(currentChar);
            break;
        }
      }

      string returnValue = result.ToString();

      if (!keepTrailingNewline)
      {
        returnValue = returnValue.TrimEnd();
      }

      return returnValue;
    }


    public byte[] ReadBinaryLine()
    {
      MemoryStream memStream = new MemoryStream();
      bool foundEndOfLine = false;
      byte ch;

      while (!foundEndOfLine)
      {
        try
        {
          ch = base.ReadByte();
        }
        catch (EndOfStreamException ex)
        {
          Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadBinaryLine(EndOfStreamException): Client request header: {0}", ex.Message);

          if (memStream.Length == 0)
          {
            return null;
          }
          else
          {
            break;
          }
        }

        switch (ch)
        {
          case 0x0d:
            memStream.WriteByte(ch);
            try
            {
              if (base.PeekChar() == 0x0a)
              {
                ch = base.ReadByte();
                memStream.WriteByte(ch);
              }
            }
            catch (Exception ex)
            {
              Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadBinaryLine(Exception): {0}", ex.Message);
            }

            foundEndOfLine = true;
            break;
          case 0x0a:
            memStream.WriteByte(ch);
            foundEndOfLine = true;
            break;
          default:
            memStream.WriteByte(ch);
            break;
        }
      }

      return memStream.GetBuffer();
    }

    #endregion

  }
}
