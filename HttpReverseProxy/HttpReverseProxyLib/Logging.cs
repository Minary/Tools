namespace HttpReverseProxyLib
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Text.RegularExpressions;


  public class Logging
  {

    #region MEMBERS

    private static Logging instance;
    private static StreamWriter logFileStreamWriter;
    private static string logfilePath;
    private static string logFileName = "HttpProxy.log";
    private object syncObj = new object();
    private List<string> logs = new List<string>();
    private Loglevel logLevel;
    private bool isInTestingMode;

    #endregion


    #region PROPERTIES

    public static Logging Instance { get { return instance ?? (instance = GetInstance()); } set { } }

    public Loglevel LoggingLevel { get { return this.logLevel; } set { this.logLevel = value; } }

    public bool IsInTestingMode { get { return this.isInTestingMode; } set { this.isInTestingMode = value; } }

    #endregion


    #region PUBLIC

    public void LogMessage(string requestId, ProxyProtocol proxyProtocol, Loglevel logLevel, string message, params object[] messageParams)
    {
      if (string.IsNullOrEmpty(message) || string.IsNullOrWhiteSpace(message))
      {
        return;
      }

      if (logLevel < this.logLevel)
      {
        return;
      }

      if (string.IsNullOrEmpty(requestId))
      {
        requestId = "UNDEF";
      }

      try
      {
        // Prepare log message
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        if (messageParams != null && messageParams.Length > 0)
        {
          message = string.Format(message, messageParams);
        }

        message = message.Trim();

        lock (this.syncObj)
        {
          string logMessage = string.Format("{0} {1} {2}: {3}", timestamp, requestId, proxyProtocol, message);
          logFileStreamWriter.WriteLine(logMessage);
          logFileStreamWriter.Flush();
          logFileStreamWriter.BaseStream.Flush();

Console.WriteLine(logMessage);
          // If testing this application add record to array
          if (this.isInTestingMode)
          {
            string logLine = string.Format("{0} {1}: {2}{3}", timestamp, requestId, message, Environment.NewLine);
            this.logs.Add(logLine);
          }
        }
      }
      catch (Exception ex)
      {
        if (logLevel == Loglevel.Debug)
        {
          Console.WriteLine("ERROR: Error occurred in LogMessage: {0}", ex.Message);
        }
      }
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="searchPattern"></param>
    /// <returns></returns>
    public List<string> FindLogRecordByRegex(string searchPattern)
    {
      List<string> foundLogRecords = new List<string>();

      foreach (string tmpLogRecord in this.logs)
      {
        if (Regex.Match(tmpLogRecord, searchPattern, RegexOptions.IgnoreCase).Success)
        {
          foundLogRecords.Add(tmpLogRecord);
        }
      }

      return foundLogRecords;
    }


    public void DumpLogRecords()
    {
      foreach (string tmpLogRecord in this.logs)
      {
        Console.WriteLine("LOG: {0}", tmpLogRecord.Trim());
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void ResetLogging()
    {
      this.logs.Clear();
    }

    #endregion


    #region PRIVATE

    /// <summary>
    /// Initializes a new instance of the <see cref="Logging"/> class.
    ///
    /// </summary>
    /// <param name="logLevel"></param>
    private Logging(Loglevel logLevel = Loglevel.Debug)
    {
      this.logLevel = logLevel;
    }


    private static Logging GetInstance()
    {
      Logging instance = new Logging();

      // Close log file stream if it is still open.
      try
      {
        if (logFileStreamWriter != null)
        {
          logFileStreamWriter.Close();
        }
      }
      catch
      {
      }

      // Open log file stream
      try
      {
        logfilePath = Path.Combine(Directory.GetCurrentDirectory(), logFileName);
        logFileStreamWriter = File.AppendText(logFileName);
        logFileStreamWriter.AutoFlush = true;
      }
      catch
      {
      }

      return instance;
    }

    #endregion

  }
}
