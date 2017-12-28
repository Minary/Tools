namespace HttpReverseProxy.Plugin.SslStrip.DataTypes.Configuration
{
  using System.Collections.Concurrent;


  public class HtmlTagConfig
  {

    #region PROPERTIES

    public ConcurrentDictionary<string, bool> TagList { get; set; }

    #endregion


    #region PUBLIC

    /// <summary>
    /// Initializes a new instance of the <see cref="HtmlTagConfig"/> class.
    ///
    /// </summary>
    public HtmlTagConfig()
    {
      TagList = new ConcurrentDictionary<string, bool>();
    }

    #endregion

  }
}
