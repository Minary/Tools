// Record
namespace HttpReverseProxy.Plugin.RequestRedirect.DataTypes
{
  using System.Text.RegularExpressions;


  public class RequestRedirectConfigRecord
  {

    #region PROPERTIES

    public string RedirectType { get; set; } = string.Empty;

    public string RedirectDescription { get; set; } = string.Empty;

    public string HostnameStr { get; set; } = string.Empty;

    public Regex HostnameRegex { get; set; }

    public string PathStr { get; set; } = string.Empty;

    public Regex PathRegex { get; set; }

    public string ReplacementResource { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public RequestRedirectConfigRecord(string redirectType, string redirectDescription, string host, string path, string replacementResource)
    {
      this.RedirectType = redirectType;
      this.RedirectDescription = redirectDescription;
      this.HostnameStr = host;
      this.PathStr = path;
      this.ReplacementResource = replacementResource;
    }

    #endregion 

  }
}
