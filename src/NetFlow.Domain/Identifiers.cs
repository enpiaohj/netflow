namespace NetFlow.Domain;

/// <summary>强类型标识符。全部以 Guid 承载，避免 ID 混用。</summary>
public readonly record struct RunId(Guid Value)
{
    public static RunId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

public readonly record struct ProbeId(Guid Value)
{
    public static ProbeId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

public readonly record struct EvidenceId(Guid Value)
{
    public static EvidenceId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

public readonly record struct FindingId(Guid Value)
{
    public static FindingId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

public readonly record struct ArtifactId(Guid Value)
{
    public static ArtifactId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}
