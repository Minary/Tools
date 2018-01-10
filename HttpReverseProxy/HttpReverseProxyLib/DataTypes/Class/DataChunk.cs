namespace HttpReverseProxyLib.DataTypes.Class
{
  using System.Text;


  public class DataChunk
  {

    #region PROPERTIES

    public byte[] ContentData { get; set; }

    public int ContentDataLength { get; set; }

    public Encoding DataEncoding { get; set; }

    #endregion


    #region PUBLIC

    public DataChunk(byte[] contentData, int contentDataLength, Encoding dataEncoding)
    {
      this.ContentData = contentData;
      this.ContentDataLength = contentDataLength;
      this.DataEncoding = dataEncoding;
    }

    #endregion

  }
}
