package trabe;

public class AbeDecryptionException extends DecryptionException {

	private static final long serialVersionUID = 2848983353356933397L;

	public AbeDecryptionException(final String msg) {
		super(msg);
	}

	public AbeDecryptionException(final String msg, final Throwable t) {
		super(msg, t);
	}
}
