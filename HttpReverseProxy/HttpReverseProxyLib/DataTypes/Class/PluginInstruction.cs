namespace HttpReverseProxyLib.DataTypes
{
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System.Collections.Generic;


  public class PluginInstruction
  {

    #region PROPERTIES

    public Instruction Instruction { get; set; }

    public InstructionParams InstructionParameters { get; set; }

    #endregion


    #region PUBLIC

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstruction"/> class.
    ///
    /// </summary>
    /// <param name="instruction"></param>
    /// <param name="url"></param>
    /// <param name="status"></param>
    /// <param name="data"></param>
    /// <param name="httpHeaders"></param>
    public PluginInstruction(Instruction instruction, string url, string status, string data, List<string> httpHeaders)
    {
      this.Instruction = instruction;
      this.InstructionParameters = new InstructionParams();

      this.InstructionParameters.Url = url;
      this.InstructionParameters.Status = status;
      this.InstructionParameters.Data = data;
      this.InstructionParameters.HttpHeaders = httpHeaders;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstruction"/> class.
    ///
    /// </summary>
    public PluginInstruction()
    {
      this.Instruction = Instruction.DoNothing;
      this.InstructionParameters = new InstructionParams();
      this.InstructionParameters.Url = string.Empty;
      this.InstructionParameters.Status = string.Empty;
      this.InstructionParameters.Data = string.Empty;
      this.InstructionParameters.HttpHeaders = new List<string>();
    }

    #endregion

  }
}
