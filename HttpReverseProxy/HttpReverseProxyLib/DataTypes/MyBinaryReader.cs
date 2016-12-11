namespace HttpReverseProxyLib.DataTypes
{
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
Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, "HttpReverseProxyLib.MyBinaryReader.ReadLine(EndOfStreamException): TIMEOUT IS={0} ", base.BaseStream.ReadTimeout);
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
            //try
            //{
            //  int peekChar;
            //  if ((peekChar = base.PeekChar()) == '\n')
            //  {
            //    currentChar = base.ReadChar();
            //    result.Append(currentChar);
            //  }
            //}
            //catch (Exception ex)
            //{
            //  Logging.Instance.LogMessage(this.clientConnectionId, Logging.Level.DEBUG, string.Format("HttpReverseProxyLib.MyBinaryReader.ReadLine(Exception): {0}", ex.Message), Logging.Level.DEBUG);
            //}
            //foundEndOfLine = true;
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
