void init() {
        // BLOCK: 
    // Block_io_init
    Vfs::Vfs_handle &block_file = fs.open(
                                            "/tresor/container.img",
                                            Vfs::Directory_service::OPEN_MODE_RDWR
                                        );
    // Создать Block_io для низкоуровневого доступа
    Block_io block_io { block_file };

    // BLOCK:
    // trust_anchor_init
    // Открыть файлы управления trust anchor
    Vfs::Vfs_handle &ta_decrypt_file = fs.open("/tresor_ta/decrypt", Vfs::Directory_service::OPEN_MODE_RDWR);
    Vfs::Vfs_handle &ta_encrypt_file = fs.open("/tresor_ta/encrypt", Vfs::Directory_service::OPEN_MODE_RDWR);
    Vfs::Vfs_handle &ta_generate_key_file = fs.open("/tresor_ta/generate_key", Vfs::Directory_service::OPEN_MODE_RDWR);
    Vfs::Vfs_handle &ta_initialize_file = fs.open("/tresor_ta/initialize", Vfs::Directory_service::OPEN_MODE_RDWR);
    Vfs::Vfs_handle &ta_hash_file = fs.open("/tresor_ta/hash", Vfs::Directory_service::OPEN_MODE_RDWR);

    // Создать Trust anchor
    Trust_anchor::Attr ta_attr {
        .decrypt_file = ta_decrypt_file,
        .encrypt_file = ta_encrypt_file,
        .generate_key_file = ta_generate_key_file,
        .initialize_file = ta_initialize_file,
        .hash_file = ta_hash_file
    };

    Trust_anchor trust_anchor { ta_attr };

    // BLOCK:
    // Crypto
    // Реализовать интерфейс для управления ключами
    struct My_crypto_keys : Tresor::Crypto_key_files_interface {
        void add_crypto_key(Key_id id) override {
            // Добавить ключ с ID id
        }
        void remove_crypto_key(Key_id id) override {
            // Удалить ключ с ID id
        }
        Vfs::Vfs_handle &encrypt_file(Key_id id) override {
            // Вернуть файл для шифрования ключа id
        }
        Vfs::Vfs_handle &decrypt_file(Key_id id) override {
            // Вернуть файл для расшифровки ключа id
        }
    };

    My_crypto_keys my_keys;
    Vfs::Vfs_handle &crypto_add_key_file = fs.open(
        "/tresor_crypto/add_key", Vfs::Directory_service::OPEN_MODE_WRONLY);
    Vfs::Vfs_handle &crypto_remove_key_file = fs.open(
        "/tresor_crypto/remove_key", Vfs::Directory_service::OPEN_MODE_WRONLY);

    Crypto::Attr crypto_attr {
        .key_files = my_keys,
        .add_key_file = crypto_add_key_file,
        .remove_key_file = crypto_remove_key_file
    };

    Crypto crypto { crypto_attr };

    // BLOCK:
    // Initializers
    Vbd_initializer vbd_initializer;
    Ft_initializer ft_initializer;
    Sb_initializer sb_initializer;

    // BLOCK
    // TA init
    // Создать объект инициализации Trust Anchor
    Trust_anchor::Initialize ta_init { 
        {.in_passphrase = Passphrase("MySecurePassword123")}
    };

    // Выполнять initialize в цикле до завершения
    while (!ta_init.complete()) {
        if (ta_init.execute(trust_anchor.get_attr())) {
            // Операция выполнена, проверить результат
        }
        // Обработать асинхронные события
    }

    if (ta_init.success()) {
        log("Trust Anchor initialized successfully");
    } else {
        error("Trust Anchor initialization failed");
    }

    // BLOCK
    // Superblock config
    // Создать конфигурацию для VBD
    Tree_configuration vbd_config {
        .max_lvl = VBD_MAX_LEVEL,
        .degree = VBD_DEGREE,
        .num_leaves = VBD_NUM_LEAVES
    };

    // Создать конфигурацию для Free Tree
    Tree_configuration ft_config {
        .max_lvl = FT_MAX_LEVEL,
        .degree = FT_DEGREE,
        .num_leaves = FT_NUM_LEAVES
    };

    // Создать конфигурацию суперблока
    Superblock_configuration sb_config {
        .vbd = vbd_config,
        .free_tree = ft_config
    };

    // BLOCK
    // Trees init
    Pba_allocator pba_alloc { NR_OF_SUPERBLOCK_SLOTS };

    // 1. Инициализировать Free Tree
    Ft_initializer::Initialize ft_init { 
        {
            .in_tree_cfg = ft_config,
            .out_tree_root = /* ссылка на корень FT */,
            .in_out_pba_alloc = pba_alloc
        }
    };

    while (!ft_init.complete()) {
        if (ft_initializer.execute(ft_init, block_io)) {
            // Прогресс
        }
    }

    // 2. Инициализировать VBD
    Vbd_initializer::Initialize vbd_init {
        {
            .in_tree_cfg = vbd_config,
            .out_tree_root = /* ссылка на корень VBD */,
            .in_out_pba_alloc = pba_alloc
        }
    };

    while (!vbd_init.complete()) {
        if (vbd_initializer.execute(vbd_init, block_io)) {
            // Прогресс
        }
    }

    // 3. Инициализировать суперблоки
    Sb_initializer::Initialize sb_init {
        {
            .in_sb_cfg = sb_config,
            .in_out_pba_alloc = pba_alloc
        }
    };

    while (!sb_init.complete()) {
        if (sb_initializer.execute(sb_init, block_io, trust_anchor, 
                                vbd_initializer, ft_initializer)) {
            // Прогресс
        }
    }

    if (sb_init.success()) {
        log("Container initialized successfully");
    } else {
        error("Container initialization failed");
    }
}