namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  public class HstsRecord
  {

    #region MEMBER

    private int counter = 0;
    private string host;
    private bool encryptSubdomains;

    #endregion


    #region Properties

    public int Counter { get { return this.counter; } set { this.counter = value; } }
    public string Host { get { return this.host; } set { this.host = value; } }
    public bool EncryptSubdomains { get { return encryptSubdomains; } set { encryptSubdomains = value; } }

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    /// Initializes a new instance of the <see cref="HstsRecord"/> class.
    ///
    /// </summary>
    /// <param name="host"></param>
    public HstsRecord(string host)
    {
      this.Host = host;
    }

    #endregion

  }
}
