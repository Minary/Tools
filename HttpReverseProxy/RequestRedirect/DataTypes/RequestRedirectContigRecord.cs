// Record
namespace HttpReverseProxy.Plugin.RequestRedirect.DataTypes
{

  public class RequestRedirectConfigRecord
  {

    #region MEMBERS

    private string redirectType;
    private string redirectDescription;
    private string host;
    private string path;
    private string replacementResource;

    #endregion


    #region PROPERTIES

    public string RedirectType { get { return this.redirectType; } set { this.redirectType = value; } }

    public string RedirectDescription { get { return this.redirectDescription; } set { this.redirectDescription = value; } }

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public string ReplacementResource { get { return this.replacementResource; } set { this.replacementResource = value; } }

    #endregion


    #region PUBLIC

    public RequestRedirectConfigRecord()
    {
      this.redirectType = string.Empty;
      this.redirectDescription = string.Empty;
      this.host = string.Empty;
      this.path = string.Empty;
      this.replacementResource = string.Empty;
    }

    public RequestRedirectConfigRecord(string redirectType, string redirectDescription, string host, string path, string replacementResource)
    {
      this.redirectType = redirectType;
      this.redirectDescription = redirectDescription;
      this.host = host;
      this.path = path;
      this.replacementResource = replacementResource;
    }

    #endregion 

  }
}
