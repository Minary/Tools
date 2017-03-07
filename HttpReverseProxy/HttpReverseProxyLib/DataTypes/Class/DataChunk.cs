namespace HttpReverseProxyLib.DataTypes.Class
{
  using System.Text;


  public class DataChunk
  {

    #region PRIVATE

    private byte[] contentData;
    private Encoding dataEncoding;

    #endregion


    #region PROPERTIES

    public byte[] ContentData { get { return this.contentData; } set { this.contentData = value; } }

    public Encoding DataEncoding { get { return this.dataEncoding; } set { this.dataEncoding = value; } }

    #endregion


    #region PUBLIC

    public DataChunk(byte[] contentData, Encoding dataEncoding)
    {
      this.contentData = contentData;
      this.dataEncoding = dataEncoding;
    }

    #endregion

  }
}
