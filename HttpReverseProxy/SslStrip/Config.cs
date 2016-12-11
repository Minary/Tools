﻿namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxy.Plugin.SslStrip.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.Exceptions;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Config
  {

    #region MEMBERS

    private static string pluginName = "SslStrip";
    private static int pluginPriority = 2;
    private static string pluginVersion = "0.1";
    private static string configFileName = "plugin.config";

    private Dictionary<string, List<string>> searchPatterns = new Dictionary<string, List<string>>();
    private List<string> searchPatternTemplates = new List<string>()
               {
                                 @"<\s*a\s+[^>]*href\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*base\s+[^>]*href\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*link\s+[^>]*href\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*form\s+[^>]*action\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*script\s+[^>]*src\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*img\s+[^>]*src\s*=\s*""(https://{0})([^""]*)""[^>]*>",
                                 @"<\s*iframe\s+[^>]*src\s*=\s*""(https://{0})([^""]*)""[^>]*>"
               };

    #endregion


    #region PROPERTIES

    public static string PluginName { get { return pluginName; } set { } }

    public static int PluginPriority { get { return pluginPriority; } set { } }

    public static string PluginVersion { get { return pluginVersion; } set { } }

    public static string ConfigFileName { get { return configFileName; } set { } }

    public Dictionary<string, List<string>> SearchPatterns { get { return this.searchPatterns; } set { } }

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
        SslStripConfigRecord configRecord = null;
        try
        {
          configRecord = this.VerifyRecordParameters(tmpLine);
        }
        catch (ProxyWarningException pwex)
        {
          Logging.Instance.LogMessage("CONFIG", Logging.Level.DEBUG, @"Inject.VerifyRecordParameters(EXCEPTION): {0}", pwex.Message);
          continue;
        }
        catch (ProxyErrorException peex)
        {
          Logging.Instance.LogMessage("CONFIG", Logging.Level.DEBUG, @"Inject.VerifyRecordParameters(EXCEPTION): {0}", peex.Message);
          continue;
        }

        // Generate regex per host/contentype
        if (!this.searchPatterns.ContainsKey(configRecord.ContentType))
        {
          this.searchPatterns.Add(configRecord.ContentType, new List<string>());
        }

        foreach (string tmpTemplate in this.searchPatternTemplates)
        {
          string realPattern = string.Format(tmpTemplate, Regex.Escape(configRecord.Host));
          Console.WriteLine("Regex:|{0}|", realPattern);
          this.searchPatterns[configRecord.ContentType].Add(realPattern);
        }
      }
    }

    #endregion


    #region PROTECTED

    protected SslStripConfigRecord VerifyRecordParameters(string configFileLine)
    {
      string host = string.Empty;
      string contentType = string.Empty;
      char[] delimiter = { ':' };

      if (string.IsNullOrEmpty(configFileLine))
      {
        throw new ProxyWarningException("Configuration line is invalid");
      }

      string[] splitter = configFileLine.Split(delimiter, 2);
      if (splitter.Length != 2)
      {
        throw new ProxyWarningException("Configuration is invalid");
      }

      host = splitter[0];
      contentType = splitter[1];

      // Parse parameters
      if (string.IsNullOrEmpty(host) || string.IsNullOrWhiteSpace(host))
      {
        throw new ProxyWarningException(string.Format("Host parameter is invalid: {0}", splitter[0]));
      }

      if (string.IsNullOrEmpty(contentType) || string.IsNullOrWhiteSpace(contentType))
      {
        throw new ProxyWarningException(string.Format("MIME-Type parameter is invalid: {0}", splitter[1]));
      }

      return new SslStripConfigRecord(host, contentType);
    }

    #endregion

  }
}