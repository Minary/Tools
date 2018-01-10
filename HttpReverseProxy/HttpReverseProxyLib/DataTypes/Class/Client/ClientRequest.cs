namespace HttpReverseProxyLib.DataTypes.Class.Client
{
  using System.Collections.Generic;
  using System.IO;


  public class ClientRequest
  {

    #region MEMBERS

    private string defaultHost;

    #endregion


    #region PROPERTIES

    public string Host { get; set; }

    public ClientRequestLine RequestLine { get; set; }

    public string Scheme { get; set; }

    public bool IsClientKeepAlive { get; set; }

    public DataContentTypeEncoding ContentTypeEncoding { get; set; }

    public IncomingClientRequest ClientWebRequestHandler { get; set; }

    public Dictionary<string, List<string>> ClientRequestHeaders { get; set; }

    public MyBinaryReader ClientBinaryReader { get; set; }

    public BinaryWriter ClientBinaryWriter { get; set; }

    public int ContentLength { get; set; }

    public string ClientRequestData { get; set; }

    #endregion


    #region PUBLIC

    public ClientRequest(string defaultHost)
    {
      this.RequestLine = new ClientRequestLine();
      this.defaultHost = defaultHost;

      this.ContentLength = 0;
      this.ClientRequestHeaders = new Dictionary<string, List<string>>();
      this.ContentTypeEncoding = new DataContentTypeEncoding();
      this.ClientBinaryReader = null;
      this.ClientBinaryWriter = null;

      this.Scheme = "http";
      this.Host = string.Empty;
      this.IsClientKeepAlive = false;
    }


    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public string GetRequestedUrl()
    {
      var requestUrl = string.Empty;

      if (!string.IsNullOrEmpty(this.Host))
      {
        requestUrl = $"{this.Scheme}://{this.Host}{this.RequestLine.Path}";
      }
      else
      {
        requestUrl = $"{this.Scheme}://{this.defaultHost}{this.RequestLine.Path}";
      }

      return requestUrl;
    }

    #endregion

  }
}
