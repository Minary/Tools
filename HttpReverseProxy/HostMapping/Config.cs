namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
  using System.IO;


  public class Config
  {

    #region MEMBERS

    private static string pluginName = "HostMapping";
    private static int pluginPriority = 1;
    private static string pluginVersion = "0.1";
    private static string configFileName = "plugin.config";

    private static Dictionary<string, Tuple<string, string>> mappings = new Dictionary<string, Tuple<string, string>>();

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    public static string ConfigFileName { get { return configFileName; } set { } }

    public static Dictionary<string, Tuple<string, string>> Mappings { get { return mappings; } set { } }

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
        if (string.IsNullOrEmpty(tmpLine))
        {
          continue;
        }

        if (!tmpLine.Contains(":"))
        {
          continue;
        }

        // Data structure is: RequestedHost:MappedHostScheme:MappedHost
        string[] splitter = tmpLine.Split(new char[] { ':' });

        if (splitter.Length != 3)
        {
          continue;
        }

        // Generate regex per host/contentype
        if (!mappings.ContainsKey(splitter[0]))
        {
          mappings.Add(splitter[0].ToLower(), new Tuple<string, string>(splitter[1], splitter[2]));
        }
      }
    }

    #endregion

  }
}