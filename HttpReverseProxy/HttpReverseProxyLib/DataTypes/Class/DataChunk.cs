namespace HttpReverseProxyLib.DataTypes.Class
{
  using System.Text;


  public class DataChunk
  {

    #region PRIVATE

    private byte[] contentData;
    private int contentDataLength;
    private Encoding dataEncoding;

    #endregion


    #region PROPERTIES

    public byte[] ContentData { get { return this.contentData; } set { this.contentData = value; } }

    public int ContentDataLength { get { return this.contentDataLength; } set { this.contentDataLength = value; } }

    public Encoding DataEncoding { get { return this.dataEncoding; } set { this.dataEncoding = value; } }

    #endregion


    #region PUBLIC

    public DataChunk(byte[] contentData, int contentDataLength, Encoding dataEncoding)
    {
      this.contentData = contentData;
      this.contentDataLength = contentDataLength;
      this.dataEncoding = dataEncoding;
    }

    #endregion

  }
}
