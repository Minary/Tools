namespace HttpReverseProxyLib.Exceptions
{
  using System;

  public class EmptyRequestException: Exception
  {
    public EmptyRequestException()
      : base()
    {
    }

    public EmptyRequestException(string message)
      : base(message)
    {
    }
  }
}
