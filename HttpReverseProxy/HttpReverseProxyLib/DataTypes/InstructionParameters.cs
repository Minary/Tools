namespace HttpReverseProxyLib.DataTypes
{
  using System.Collections.Generic;

  public class InstructionParams
  {

    #region MEMBERS

    private Instruction instruction;
    private string url;
    private string status;
    private string data;
    private List<string> httpHeaders;

    #endregion


    #region PROPERTIES

    public Instruction Instruction { get { return instruction; } set { instruction = value; } }
    public string Url { get { return this.url; } set { this.url = value; } }
    public string Status { get { return this.status; } set { this.status = value; } }
    public string Data { get { return this.data; } set { this.data = value; } }
    public List<string> HTTPHeaders { get { return this.httpHeaders; } set { this.httpHeaders = value; } }

    #endregion

  }
}
