namespace HttpReverseProxyLib.Exceptions
{
  using System;

  public class ProxyErrorException : Exception
  {

    public ProxyErrorException(string message) :
      base(message)
    {
    }
  }
}
