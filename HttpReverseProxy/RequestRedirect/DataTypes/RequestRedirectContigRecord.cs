// Record
namespace HttpReverseProxy.Plugin.RequestRedirect.DataTypes
{

  public class RequestRedirectConfigRecord
  {

    #region MEMBERS

    private string host;
    private string path;
    private string replacementResource;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public string ReplacementResource { get { return this.replacementResource; } set { this.replacementResource = value; } }

    #endregion


    #region PUBLIC

    public RequestRedirectConfigRecord()
    {
      this.host = string.Empty;
      this.path = string.Empty;
      this.replacementResource = string.Empty;
    }

    public RequestRedirectConfigRecord(string host, string path, string replacementResource)
    {
      this.host = host;
      this.path = path;
      this.replacementResource = replacementResource;
    }

    #endregion 

  }
}
