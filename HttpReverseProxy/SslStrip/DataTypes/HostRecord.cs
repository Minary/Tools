namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  using HttpReverseProxyLib.DataTypes.Enum;


  public class HostRecord
  {

    #region MEMBERS

//private string scheme;
private ProxyProtocol proxyProtocol;
    private string method;
    private string host;
    private string path;
    private int counter;


    #endregion


    #region PROPERTIES

    public string Url { get { return string.Format("{0}://{1}{2}", this.proxyProtocol.ToString().ToLower(), this.host, this.path); } }

//public string Scheme { get { return scheme; } set { scheme = value; } }
    public ProxyProtocol ProxyProtocol { get { return this.proxyProtocol; } set { this.proxyProtocol = value; } }

    public string Method { get { return this.method; } set { this.method = value; } }

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public int Counter { get { return this.counter; } set { } }

    #endregion


    #region PUBLIC METHODS

    public HostRecord(string method, ProxyProtocol proxyProtocol, string host, string path)
    {
      this.method = method;
      //this.scheme = scheme;
      this.proxyProtocol = proxyProtocol;
      this.host = host;
      this.path = path;
      this.counter = 0;
    }

    public void IncCounter()
    {
      this.counter++;
    }

    #endregion

  }
}
