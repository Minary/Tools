namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{
  public class HstsRecord
  {

    #region Properties

    public int Counter { get; set; } = 0;

    public string Host { get; set; } = string.Empty;

    public bool EncryptSubdomains { get; set; } = false;

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
