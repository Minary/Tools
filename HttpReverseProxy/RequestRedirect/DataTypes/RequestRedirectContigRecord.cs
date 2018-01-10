// Record
namespace HttpReverseProxy.Plugin.RequestRedirect.DataTypes
{

  public class RequestRedirectConfigRecord
  {

    #region PROPERTIES

    public string RedirectType { get; set; } = string.Empty;

    public string RedirectDescription { get; set; } = string.Empty;

    public string HostRegex { get; set; } = string.Empty;

    public string PathRegex { get; set; } = string.Empty;

    public string ReplacementResource { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public RequestRedirectConfigRecord(string redirectType, string redirectDescription, string hostRegex, string pathRegex, string replacementResource)
    {
      this.RedirectType = redirectType;
      this.RedirectDescription = redirectDescription;
      this.HostRegex = hostRegex;
      this.PathRegex = pathRegex;
      this.ReplacementResource = replacementResource;
    }

    #endregion 

  }
}
