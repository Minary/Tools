namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  public class HostRecord
  {

    #region MEMBERS

    private string scheme;
    private string method;
    private string host;
    private string path;
    private int counter;

    #endregion


    #region PROPERTIES

    public string Url { get { return string.Format("{0}://{1}{2}", this.scheme, this.host, this.path); } }
    public string Scheme { get { return scheme; } set { scheme = value; } }
    public string Method { get { return method; } set { method = value; } }
    public string Host { get { return host; } set { host = value; } }
    public string Path { get { return path; } set { path = value; } }
    public int Counter { get { return this.counter; } set { } }

    #endregion


    #region PUBLIC METHODS

    public HostRecord(string method, string scheme, string host, string path)
    {
      this.method = method;
      this.scheme = scheme;
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
