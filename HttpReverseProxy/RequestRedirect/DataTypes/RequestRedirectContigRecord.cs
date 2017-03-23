// Record
namespace HttpReverseProxy.Plugin.RequestRedirect.DataTypes
{

  public class RequestRedirectConfigRecord
  {

    #region MEMBERS

    private string redirectType;
    private string redirectDescription;
    private string hostRegex;
    private string pathRegex;
    private string replacementResource;

    #endregion


    #region PROPERTIES

    public string RedirectType { get { return this.redirectType; } set { this.redirectType = value; } }

    public string RedirectDescription { get { return this.redirectDescription; } set { this.redirectDescription = value; } }

    public string HostRegex { get { return this.hostRegex; } set { this.hostRegex = value; } }

    public string PathRegex { get { return this.pathRegex; } set { this.pathRegex = value; } }

    public string ReplacementResource { get { return this.replacementResource; } set { this.replacementResource = value; } }

    #endregion


    #region PUBLIC

    public RequestRedirectConfigRecord()
    {
      this.redirectType = string.Empty;
      this.redirectDescription = string.Empty;
      this.hostRegex = string.Empty;
      this.pathRegex = string.Empty;
      this.replacementResource = string.Empty;
    }

    public RequestRedirectConfigRecord(string redirectType, string redirectDescription, string hostRegex, string pathRegex, string replacementResource)
    {
      this.redirectType = redirectType;
      this.redirectDescription = redirectDescription;
      this.hostRegex = hostRegex;
      this.pathRegex = pathRegex;
      this.replacementResource = replacementResource;
    }

    #endregion 

  }
}
