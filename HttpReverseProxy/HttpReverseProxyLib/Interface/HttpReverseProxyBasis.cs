namespace HttpReverseProxyLib
{
  using System;
  using System.IO;
  using System.Text.RegularExpressions;


  public abstract class HttpReverseProxyBasis
  {

    #region PUBLIC

    public string DetermineCertificatePath(string certificateHost)
    {
      var certificateBaseFileName = Regex.Replace(certificateHost, @"[^\d\w_]", "_");
      var certificateFileName = $"{certificateBaseFileName}.pfx";
      var certificateFullPath = Path.Combine(Directory.GetCurrentDirectory(), certificateFileName);

      return certificateFullPath;
    }


    public string CreateCertificate(string certificateHost)
    {
      var certificateFullPath = this.DetermineCertificatePath(certificateHost);
      var certificateFileName = Path.GetFileName(certificateFullPath);
      var validityStartDate = DateTime.Now.AddDays(-1);
      var validityEndDate = DateTime.Now.AddYears(5);

      Console.WriteLine($"Creating new certificate for host {certificateHost}");

      // Delete certificate file if it already exists
      if (File.Exists(certificateFullPath))
      {
        Console.WriteLine("Certificate file \"{0}\" already exists. You have to (re)move the file in order to create a new certificate.", certificateFileName);
        return certificateFullPath;
      }      

      // Create certificate
      NativeWindowsLib.Crypto.Crypto.CreateNewCertificate(certificateFileName, certificateHost, validityStartDate, validityEndDate);
      Console.WriteLine("Certificate created successfully.");
      Console.WriteLine("Certificate file: {0}", certificateFileName);
      Console.WriteLine("Certificate validity start: {0}", validityStartDate);
      Console.WriteLine("Certificate validity end: {0}", validityEndDate);

      return certificateFullPath;
    }

    #endregion


    #region ABSTRACT METHODS

    public abstract bool Start(int localServerPort, string certificatePath);

    public abstract void Stop();

    #endregion

  }
}
