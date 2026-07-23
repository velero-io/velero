package repomantenance

import (
	"context"
	"crypto/fips140"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bombsimon/logrusr/v3"
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerocli "github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/logging"

	repokey "github.com/vmware-tanzu/velero/pkg/repository/keys"
	"github.com/vmware-tanzu/velero/pkg/repository/maintenance"
	repomanager "github.com/vmware-tanzu/velero/pkg/repository/manager"
)

type Options struct {
	RepoName              string
	BackupStorageLocation string
	RepoType              string
	ResourceTimeout       time.Duration
	LogLevelFlag          *logging.LevelFlag
	FormatFlag            *logging.FormatFlag
}

func (o *Options) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.RepoName, "repo-name", "", "namespace of the pod/volume that the snapshot is for")
	flags.StringVar(&o.BackupStorageLocation, "backup-storage-location", "", "backup's storage location name")
	flags.StringVar(&o.RepoType, "repo-type", velerov1api.BackupRepositoryTypeKopia, "type of the repository where the snapshot is stored")
	flags.Var(o.LogLevelFlag, "log-level", fmt.Sprintf("The level at which to log. Valid values are %s.", strings.Join(o.LogLevelFlag.AllowedValues(), ", ")))
	flags.Var(o.FormatFlag, "log-format", fmt.Sprintf("The format for log output. Valid values are %s.", strings.Join(o.FormatFlag.AllowedValues(), ", ")))
}

func NewCommand(f velerocli.Factory) *cobra.Command {
	o := &Options{
		LogLevelFlag: logging.LogLevelFlag(logrus.InfoLevel),
		FormatFlag:   logging.NewFormatFlag(),
	}
	cmd := &cobra.Command{
		Use:    "repo-maintenance",
		Hidden: true,
		Short:  "VELERO INTERNAL COMMAND ONLY - not intended to be run directly by users",
		Run: func(c *cobra.Command, args []string) {
			// Disable FIPS-140 compliance check, because Kopia doesn't support FIPS-140 yet.
			fips140.WithoutEnforcement(func() {
				o.Run(f)
			})
		},
	}

	o.BindFlags(cmd.Flags())
	return cmd
}

func (o *Options) Run(f velerocli.Factory) {
	logger := logging.DefaultLogger(o.LogLevelFlag.Parse(), o.FormatFlag.Parse())
	logger.SetOutput(os.Stdout)

	ctrl.SetLogger(logrusr.New(logger))

	pruneError := o.runRepoPrune(f, f.Namespace(), logger)
	defer func() {
		if pruneError != nil {
			os.Exit(1)
		}
	}()

	if pruneError != nil {
		os.Stdout.WriteString(fmt.Sprintf("%s%v", maintenance.TerminationLogIndicator, pruneError))
	}
}

func (o *Options) initClient(f velerocli.Factory) (client.Client, error) {
	scheme := runtime.NewScheme()
	err := velerov1api.AddToScheme(scheme)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add velero scheme")
	}

	err = corev1api.AddToScheme(scheme)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add api core scheme")
	}

	config, err := f.ClientConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get client config")
	}

	cli, err := client.New(config, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}

	return cli, nil
}

func initRepoManager(namespace string, cli client.Client, kubeClient kubernetes.Interface, logger logrus.FieldLogger) (repomanager.Manager, error) {
	// ensure the repo key secret is set up
	if err := repokey.EnsureCommonRepositoryKey(kubeClient.CoreV1(), namespace); err != nil {
		return nil, errors.Wrap(err, "failed to ensure repository key")
	}

	repoLocker := repository.NewRepoLocker()

	credentialFileStore, err := credentials.NewNamespacedFileStore(
		cli,
		namespace,
		credentials.DefaultStoreDirectory(),
		filesystem.NewFileSystem(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create namespaced file store")
	}

	credentialSecretStore, err := credentials.NewNamespacedSecretStore(cli, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create namespaced secret store")
	}

	return repomanager.NewManager(
		namespace,
		cli,
		repoLocker,
		credentialFileStore,
		credentialSecretStore,
		logger,
	), nil
}

func (o *Options) runRepoPrune(f velerocli.Factory, namespace string, logger logrus.FieldLogger) error {
	cli, err := o.initClient(f)
	if err != nil {
		return err
	}

	kubeClient, err := f.KubeClient()
	if err != nil {
		return err
	}

	var repo *velerov1api.BackupRepository
	retry := 10
	for {
		repo, err = repository.GetBackupRepository(context.Background(), cli, namespace,
			repository.BackupRepositoryKey{
				VolumeNamespace: o.RepoName,
				BackupLocation:  o.BackupStorageLocation,
				RepositoryType:  o.RepoType,
			}, true)
		if err == nil {
			break
		}

		retry--
		if retry == 0 {
			break
		}

		logger.WithError(err).Warn("Failed to retrieve backup repo, need retry")

		time.Sleep(time.Second)
	}

	if err != nil {
		return errors.Wrap(err, "failed to get backup repository")
	}

	manager, err := initRepoManager(namespace, cli, kubeClient, logger)
	if err != nil {
		return err
	}

	err = manager.PruneRepo(repo)
	if err != nil {
		return errors.Wrap(err, "failed to prune repo")
	}

	return nil
}
