/*
 * \brief  Encrypted block layer using Tresor
 * \author Your Name
 * \date   2026-04-03
 *
 * This component sits between a physical block device and clients,
 * transparently encrypting/decrypting all block I/O operations.
 */

#include <base/component.h>
#include <base/attached_ram_dataspace.h>
#include <base/attached_rom_dataspace.h>
#include <base/heap.h>
#include <block/session.h>
#include <block/request_stream.h>
#include <root/root.h>
#include <vfs/simple_env.h>

/* Tresor includes */
#include <tresor/block_io.h>
#include <tresor/crypto.h>
#include <tresor/trust_anchor.h>
#include <tresor/types.h>

namespace Tresor_layer {

	using namespace Genode;
	using namespace Tresor;

	struct Encrypted_block_session;
	struct Main;

	enum { VERBOSE = 1 };
}


/**
 * Session component that encrypts/decrypts blocks on-the-fly
 */
struct Tresor_layer::Encrypted_block_session : 
	Rpc_object<Block::Session>,
	private Block::Request_stream
{
	Entrypoint &_ep;

	/* Use inherited from Request_stream */
	using Block::Request_stream::with_requests;
	using Block::Request_stream::with_content;
	using Block::Request_stream::try_acknowledge;
	using Block::Request_stream::wakeup_client_if_needed;

	/* Tresor components for encryption/decryption */
	Crypto &_crypto;
	Block_io &_block_io;

	/* Pending encryption/decryption jobs */
	struct Pending_job {
		Block::Request request;
		Constructible<Crypto::Encrypt> encrypt_job;
		Constructible<Crypto::Decrypt> decrypt_job;
		Constructible<Block_io::Read> read_job;
		Constructible<Block_io::Write> write_job;
		Block _buffer;
		enum State {
			IDLE,
			READING_PHYSICAL,
			DECRYPTING,
			WRITING_LOGICAL,
			READING_LOGICAL,
			ENCRYPTING,
			WRITING_PHYSICAL,
			COMPLETE
		} state;
	};

	static constexpr unsigned MAX_JOBS = 4;
	Pending_job _jobs[MAX_JOBS];

	/* Key ID to use for encryption */
	Key_id _key_id;

	Encrypted_block_session(Env::Local_rm &rm,
	                        Dataspace_capability ds,
	                        Entrypoint &ep,
	                        Signal_context_capability sigh,
	                        Crypto &crypto,
	                        Block_io &block_io,
	                        size_t block_size,
	                        size_t num_blocks,
	                        Key_id key_id)
	:
		Request_stream(rm, ds, ep, sigh,
		              Info { .block_size  = block_size,
		                     .block_count = num_blocks,
		                     .align_log2  = log2(block_size, 0u),
		                     .writeable   = true },
		              Block::Constrained_view { .offset = 0,
		                                        .num_blocks = 0,
		                                        .writeable = true }),
		_ep(ep),
		_crypto(crypto),
		_block_io(block_io),
		_key_id(key_id)
	{
		for (unsigned i = 0; i < MAX_JOBS; i++) {
			_jobs[i].state = Pending_job::IDLE;
		}
		_ep.manage(*this);
	}

	~Encrypted_block_session() { _ep.dissolve(*this); }

	Info info() const override { return Request_stream::info(); }

	Capability<Tx> tx_cap() override { return Request_stream::tx_cap(); }

	/**
	 * Find a free job slot
	 */
	Pending_job *_find_free_job()
	{
		for (unsigned i = 0; i < MAX_JOBS; i++) {
			if (_jobs[i].state == Pending_job::IDLE) {
				return &_jobs[i];
			}
		}
		return nullptr;
	}

	/**
	 * Process all pending I/O operations
	 */
	void _execute_jobs()
	{
		for (unsigned i = 0; i < MAX_JOBS; i++) {
			Pending_job &job = _jobs[i];

			if (job.state == Pending_job::IDLE)
				continue;

			bool progress = false;

			switch (job.state) {
			case Pending_job::READING_PHYSICAL:
				if (job.read_job->execute()) {
					progress = true;
					if (job.read_job->complete()) {
						if (job.request.operation.type == Block::Operation::Type::READ) {
							/* Decryption needed for READ */
							job.state = Pending_job::DECRYPTING;
							job.decrypt_job.construct(
								Crypto::Decrypt::Attr {
									.in_key_id = _key_id,
									.in_pba = (Physical_block_address)job.request.operation.block_number,
									.in_out_blk = job._buffer
								});
						} else {
							/* No decryption for WRITE, go directly to complete */
							job.state = Pending_job::COMPLETE;
						}
					}
				}
				break;

			case Pending_job::DECRYPTING:
				if (job.decrypt_job->execute()) {
					progress = true;
					if (job.decrypt_job->complete()) {
						job.state = Pending_job::COMPLETE;
					}
				}
				break;

			case Pending_job::ENCRYPTING:
				if (job.encrypt_job->execute()) {
					progress = true;
					if (job.encrypt_job->complete()) {
						job.state = Pending_job::WRITING_PHYSICAL;
						job.write_job.construct(
							Block_io::Write::Attr {
								.in_pba = (Physical_block_address)job.request.operation.block_number,
								.in_block = job._buffer
							});
					}
				}
				break;

			case Pending_job::WRITING_PHYSICAL:
				if (job.write_job->execute()) {
					progress = true;
					if (job.write_job->complete()) {
						job.state = Pending_job::COMPLETE;
					}
				}
				break;

			case Pending_job::COMPLETE:
				/* Will be acknowledged in with_content */
				break;

			default:
				break;
			}

			if (progress && VERBOSE) {
				log("Job ", i, " progress, state=", (unsigned)job.state);
			}
		}
	}

	/**
	 * Submit a new block I/O request
	 */
	void _submit_request(Block::Request request, char *payload_ptr)
	{
		Pending_job *job = _find_free_job();
		if (!job) {
			error("No free job slots!");
			return;
		}

		job->request = request;
		job->state = Pending_job::IDLE;

		switch (request.operation.type) {
		case Block::Operation::Type::READ:
		{
			/* For READ: read physical block, decrypt, return plaintext */
			job->state = Pending_job::READING_PHYSICAL;
			job->read_job.construct(
				Block_io::Read::Attr {
					.in_pba = (Physical_block_address)request.operation.block_number,
					.out_block = job->_buffer
				});
			break;
		}

		case Block::Operation::Type::WRITE:
		{
			/* For WRITE: encrypt plaintext, write physical block */
			job->state = Pending_job::ENCRYPTING;
			
			/* Copy plaintext from client buffer */
			Tresor::Block plaintext;
			memcpy(&plaintext, payload_ptr, BLOCK_SIZE);
			job->_buffer = plaintext;

			job->encrypt_job.construct(
				Crypto::Encrypt::Attr {
					.in_key_id = _key_id,
					.in_pba = (Physical_block_address)request.operation.block_number,
					.in_out_blk = job->_buffer
				});
			break;
		}

		case Block::Operation::Type::SYNC:
		{
			/* SYNC is a no-op for this simple implementation */
			job->state = Pending_job::COMPLETE;
			break;
		}

		default:
			error("Unsupported operation type");
			job->state = Pending_job::IDLE;
		}
	}

	/**
	 * Main event processing - called by VFS
	 */
	void process_requests()
	{
		_execute_jobs();

		with_requests([&] (Block::Request request) {
			with_content(request, [&] (char *payload_ptr, size_t payload_size) {

				if (VERBOSE) {
					log("Request: type=", (unsigned)request.operation.type,
					    " block=", request.operation.block_number,
					    " count=", request.operation.count);
				}

				_submit_request(request, payload_ptr);

				/* Check if job is already complete */
				Pending_job *job = &_jobs[0]; // simplified: assume first job
				if (job->state == Pending_job::COMPLETE) {
					if (request.operation.type == Block::Operation::Type::READ) {
						/* Copy decrypted data back to client */
						memcpy(payload_ptr, &job->_buffer, BLOCK_SIZE);
					}
					job->state = Pending_job::IDLE;
					try_acknowledge(request, true);
				}
			});
		});

		wakeup_client_if_needed();
	}
};


/**
 * Root component for creating block sessions
 */
struct Tresor_layer::Main : Rpc_object<Root>
{
	Env &_env;
	Entrypoint &_ep;
	Heap _heap { _env.ram(), _env.rm() };

	/* VFS for accessing Tresor components */
	Vfs::Simple_env _vfs_env;

	/* Tresor components */
	Vfs::Vfs_handle &_block_io_file;
	Vfs::Vfs_handle &_crypto_add_key_file;
	Vfs::Vfs_handle &_crypto_remove_key_file;
	Vfs::Vfs_handle &_ta_decrypt_file;
	Vfs::Vfs_handle &_ta_encrypt_file;
	Vfs::Vfs_handle &_ta_generate_key_file;
	Vfs::Vfs_handle &_ta_initialize_file;
	Vfs::Vfs_handle &_ta_hash_file;

	/* Mock implementations for this example */
	class Mock_crypto_key_files : public Crypto_key_files_interface
	{
	public:
		void add_crypto_key(Key_id) override { }
		void remove_crypto_key(Key_id) override { }
		Vfs::Vfs_handle &encrypt_file(Key_id) override { return _files[0]; }
		Vfs::Vfs_handle &decrypt_file(Key_id) override { return _files[1]; }

	private:
		Vfs::Vfs_handle *_files[2]; // Not used in mock
	};

	Mock_crypto_key_files _key_files;
	Block_io _block_io { _block_io_file };
	Crypto _crypto { 
		{ _key_files, _crypto_add_key_file, _crypto_remove_key_file }
	};
	Trust_anchor _trust_anchor { 
		{ _ta_decrypt_file, _ta_encrypt_file, _ta_generate_key_file,
		  _ta_initialize_file, _ta_hash_file }
	};

	Signal_handler<Main> _signal_handler { _ep, *this, &Main::_handle_signals };

	Main(Env &env) 
	:
		_env(env), 
		_ep(env.ep()),
		_vfs_env(env, _heap, _env.parent(), *this),
		_block_io_file(_open_vfs_file("block_io", 
		                               Vfs::Directory_service::OPEN_MODE_RDWR)),
		_crypto_add_key_file(_open_vfs_file("crypto/add_key",
		                                     Vfs::Directory_service::OPEN_MODE_WRONLY)),
		_crypto_remove_key_file(_open_vfs_file("crypto/remove_key",
		                                        Vfs::Directory_service::OPEN_MODE_WRONLY)),
		_ta_decrypt_file(_open_vfs_file("trust_anchor/decrypt",
		                                 Vfs::Directory_service::OPEN_MODE_RDWR)),
		_ta_encrypt_file(_open_vfs_file("trust_anchor/encrypt",
		                                 Vfs::Directory_service::OPEN_MODE_RDWR)),
		_ta_generate_key_file(_open_vfs_file("trust_anchor/generate_key",
		                                      Vfs::Directory_service::OPEN_MODE_RDWR)),
		_ta_initialize_file(_open_vfs_file("trust_anchor/initialize",
		                                    Vfs::Directory_service::OPEN_MODE_RDWR)),
		_ta_hash_file(_open_vfs_file("trust_anchor/hash",
		                              Vfs::Directory_service::OPEN_MODE_RDWR))
	{
		_ep.manage(*this);
		log("Tresor encrypted block layer started");
	}

	Vfs::Vfs_handle &_open_vfs_file(char const *path, 
	                                  Vfs::Directory_service::Open_mode mode)
	{
		using Open_result = Vfs::Directory_service::Open_result;
		Vfs::Vfs_handle *handle = nullptr;
		
		Open_result res = _vfs_env.root_dir().open(path, mode, &handle, _heap);
		if (res != Open_result::OPEN_OK) {
			error("Failed to open ", path);
		}
		return *handle;
	}

	void _handle_signals()
	{
		/* Process all pending block requests */
		// Simplified - would iterate through sessions in real implementation
	}

	/* Root interface implementation */
	Session_capability create(Session_label const &label,
	                          Root::Session_args const &args,
	                          Affinity const &affinity) override
	{
		if (VERBOSE) {
			log("Creating session for ", label);
		}

		try {
			Session_env session_env(_env);
			
			auto *session = new (_heap) Encrypted_block_session(
				session_env.rm,
				session_env.ds,
				_ep,
				_signal_handler,
				_crypto,
				_block_io,
				4096,  /* block_size */
				1024,  /* num_blocks */
				1      /* key_id */
			);

			return session->cap();
		} catch (...) {
			error("Failed to create block session");
			throw;
		}
	}

	void destroy(Session_capability) override
	{
		/* Session cleanup */
	}
};

void Component::construct(Genode::Env &env)
{
	static Tresor_layer::Main main(env);
}