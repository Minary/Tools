using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace HttpReverseProxy.Plugin.SslStrip.DataTypes.Configuration
{

  public class HtmlTagConfig
  {

    #region PROPERTIES

    public ConcurrentDictionary<string, bool> TagList { get; set; }

    #endregion


    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    public HtmlTagConfig()
    {
      TagList = new ConcurrentDictionary<string, bool>();
    }

    #endregion

  }
}
