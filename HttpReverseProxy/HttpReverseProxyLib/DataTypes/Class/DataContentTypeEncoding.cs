namespace HttpReverseProxyLib.DataTypes.Class
{
  using System.Text;


  public class DataContentTypeEncoding
  {

    #region PROPERTIES

    public string ContentType { get; set; }
    public string ContentCharSet { get; set; }
    public Encoding ContentCharsetEncoding { get; set; }

    #endregion


    #region PUBLIC

    public DataContentTypeEncoding()
    {
      this.ContentType = "text/html";
      this.ContentCharSet = "UTF-8";
      this.ContentCharsetEncoding = Encoding.GetEncoding(this.ContentCharSet);
    }


    public DataContentTypeEncoding(string contentType, string contentCharSet)
    {
      this.ContentType = contentType;
      this.ContentCharSet = contentCharSet;
      this.ContentCharsetEncoding = Encoding.GetEncoding(this.ContentCharSet);
    }

    #endregion

  }
}
