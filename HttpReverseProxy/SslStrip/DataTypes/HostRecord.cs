namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  using HttpReverseProxyLib.DataTypes.Enum;


  public class HostRecord
  {

    #region PROPERTIES
      
    public ProxyProtocol ProxyProtocol { get; set; }

    public string Method { get; set; } = string.Empty;

    public string Host { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public int Counter { get; set; }

    public string Url { get { return $"{this.ProxyProtocol.ToString().ToLower()}://{this.Host}{this.Path}"; } }

    #endregion


    #region PUBLIC METHODS

    public HostRecord(string method, ProxyProtocol proxyProtocol, string host, string path)
    {
      this.Method = method;
      this.ProxyProtocol = proxyProtocol;
      this.Host = host;
      this.Path = path;
      this.Counter = 0;
    }

    public void IncCounter()
    {
      this.Counter++;
    }

    #endregion

  }
}
