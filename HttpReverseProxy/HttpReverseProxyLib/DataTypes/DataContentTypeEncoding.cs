namespace HttpReverseProxyLib.DataTypes
{
  using System.Text;


  public class DataContentTypeEncoding
  {

    #region MEMBERS

    private string contentType;
    private string contentCharSet;
    private Encoding contentCharsetEncoding;

    #endregion


    #region PROPERTIES

    public string ContentType { get { return this.contentType; } set { this.contentType = value; } }
    public string ContentCharSet { get { return this.contentCharSet; } set { this.contentCharSet = value; } }
    public Encoding ContentCharsetEncoding { get { return this.contentCharsetEncoding; } set { this.contentCharsetEncoding = value; } }

    #endregion


    #region PUBLIC

    public DataContentTypeEncoding()
    {
      this.contentType = "text/html";
      this.contentCharSet = "UTF-8";
      this.ContentCharsetEncoding = Encoding.GetEncoding(this.contentCharSet);
    }


    public DataContentTypeEncoding(string contentType, string contentCharSet)
    {
      this.contentType = contentType;
      this.contentCharSet = contentCharSet;
      this.ContentCharsetEncoding = Encoding.GetEncoding(this.contentCharSet);
    }

    #endregion

  }
}
