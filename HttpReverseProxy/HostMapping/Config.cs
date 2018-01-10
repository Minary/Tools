namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {
    
    #region PROPERTIES

    public static string PluginName { get; private set; } = "HostMapping";

    public static int PluginPriority { get; private set; } = 1;

    public static string PluginVersion { get; private set; } = "0.1";

    public static string ConfigFileName { get; private set; } = "plugin.config";

    public static Dictionary<string, string> Mappings { get; set; } = new Dictionary<string, string>();

    #endregion


    #region PUBLIC

    /// <summary>
    ///
    /// </summary>
    /// <param name="configFilePath"></param>
    public void ParseConfigurationFile(string configFilePath)
    {
      if (string.IsNullOrEmpty(configFilePath))
      {
        throw new ProxyWarningException("Config file path is invalid");
      }

      if (!File.Exists(configFilePath))
      {
        throw new ProxyWarningException("Config file does not exist");
      }

      string[] configFileLines = File.ReadAllLines(configFilePath);
      foreach (string tmpLine in configFileLines)
      {
        if (string.IsNullOrEmpty(tmpLine) ||
            tmpLine.Contains("||") == false)
        {
          continue;
        }

        // Data structure is: RequestedHost:MappedHost
        string[] splitter = Regex.Split(tmpLine, @"\|\|");
        if (splitter.Length != 2)
        {
          continue;
        }

        // Generate regex per host/contentype
        if (!Mappings.ContainsKey(splitter[0]))
        {
          Mappings.Add(splitter[0].ToLower(),  splitter[1]);
        }
      }
    }

    #endregion

  }
}