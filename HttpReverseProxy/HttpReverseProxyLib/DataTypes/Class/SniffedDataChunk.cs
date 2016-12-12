namespace HttpReverseProxyLib.DataTypes.Class
{
  using System;
  using System.IO;
  using System.Text;


  public class SniffedDataChunk
  {

    #region MEMBERS

    private int maxDataChunkSize;
    private MemoryStream dataStream;
    private int totalBytesWritten;

    #endregion


    #region PROPERTIES

    public int TotalBytesWritten { get { return this.totalBytesWritten; } set { } }

    #endregion 


    #region PUBLIC

    public SniffedDataChunk(int maxSniffedClientDataSize)
    {
      this.maxDataChunkSize = maxSniffedClientDataSize;
      this.dataStream = new MemoryStream();
      this.totalBytesWritten = 0;
    }


    public void AppendData(byte[] data, int dataLength)
    {
      if (this.dataStream.Length < this.maxDataChunkSize && data != null && dataLength > 0)
      {
        int bytesToWrite = dataLength - ((int)this.dataStream.Length + dataLength - this.maxDataChunkSize);
        this.dataStream.Write(data, 0, dataLength);
        this.totalBytesWritten += dataLength;
      }
    }


    public string GetDataString()
    {
      string dataString = string.Empty;

      if (this.dataStream != null && this.dataStream.Length > 0)
      {
        try
        {
          byte[] dataBytes = new byte[this.totalBytesWritten];
          this.dataStream.Seek(0, SeekOrigin.Begin);
          this.dataStream.Read(dataBytes, 0, this.totalBytesWritten);

          dataString = Encoding.UTF8.GetString(dataBytes);
        }
        catch (Exception)
        {
        }
      }

      return dataString;
    }

    #endregion

  }
}
